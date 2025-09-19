// `timescale 1ns / 1ps

// module tb_binary_to_bcd_converter;

// reg [4:0] binary_input;
// wire [7:0] bcd_output;

// top_module top_module1 (
//     .binary_input(binary_input),
//     .bcd_output(bcd_output)
// );

// integer i;
// reg [4:0] test_binary;
// reg [7:0] expected_bcd;

// initial begin
//     $display("Testing Binary-to-BCD Converter...");

//     for (i = 0; i < 32; i++) begin
//         test_binary = i;
//         binary_input = test_binary;

//         // Calculate expected BCD output
//         expected_bcd[3:0] = test_binary % 10;
//         expected_bcd[7:4] = test_binary / 10;

//         #10; // Wait for the results

//         if (bcd_output !== expected_bcd) begin
//             $display("Error: Test case %0d failed. Expected BCD: 8'b%0b, Got: 8'b%0b",
//                      test_binary, expected_bcd, bcd_output);
//             $finish;
//         end
//     end

//     $display("All test cases passed!");
//     $finish;
// end

// reg vcd_clk;
// initial begin
//     $dumpfile("my_design.vcd");
//     $dumpvars(0, tb_binary_to_bcd_converter);
// end

// always #5 vcd_clk = ~vcd_clk; // Toggle clock every 5 time units

// endmodule

`timescale 1ns/1ps

module tb_binary_to_bcd_converter;

  reg  [4:0] binary_input;
  wire [7:0] bcd_output;

  // DUT instance (pure Verilog-style ports)
  top_module top_module1 (
      .binary_input(binary_input),
      .bcd_output(bcd_output)
  );

  integer i;
  reg [4:0] test_binary;
  reg [7:0] expected_bcd;

  initial begin
    $display("Testing Binary-to-BCD Converter...");

    for (i = 0; i < 32; i = i + 1) begin
      test_binary   = i[4:0];
      binary_input  = test_binary;

      // Calculate expected BCD output
      expected_bcd[3:0] = test_binary % 10;
      expected_bcd[7:4] = test_binary / 10;

      #10; // Wait for combinational settling (or a clk if your DUT is sequential)

      if (bcd_output !== expected_bcd) begin
        $display("Error: Test case %d failed. Expected BCD: 8'b%b, Got: 8'b%b",
                 test_binary, expected_bcd, bcd_output);
        $finish;
      end
    end

    $display("All test cases passed!");
    $finish;
  end

  // VCD dump (Icarus-friendly)
  reg vcd_clk;
  initial begin
    vcd_clk = 1'b0;
    $dumpfile("my_design.vcd");
    $dumpvars(0, tb_binary_to_bcd_converter);
  end

  always #5 vcd_clk = ~vcd_clk; // Free-running toggle for waveform timing

endmodule

