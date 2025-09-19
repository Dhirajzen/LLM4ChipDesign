`timescale 1ns / 1ps

module tb;

// Testbench signals
reg [4:0] binary_input;
wire [7:0] bcd_output;

// Instantiate the Design Under Test (DUT)
// Note: The module name is changed to 'top_module' to match the design
// described in the Canvas document.
top_module top_module1 (
    .binary_input(binary_input),
    .bcd_output(bcd_output)
);

// Testbench variables
integer i;
reg [4:0] test_binary;
reg [7:0] expected_bcd;
integer errors = 0;
integer clocks = 0;

// Main simulation block
initial begin
    $display("Testing Binary-to-BCD Converter...");
    $display("Time\tBinary\tExpected\tActual\tResult");
    $display("-------------------------------------------------");

    for (i = 0; i < 32; i = i + 1) begin
        // Apply the test vector
        test_binary = i;
        binary_input = test_binary;

        // Calculate the expected BCD output using behavioral logic
        expected_bcd = (test_binary / 10) * 8'd16 + (test_binary % 10);

        // Increment the clock counter
        clocks = clocks + 1;

        // Wait for a time unit for the combinational logic to propagate
        #10;

        // Check for mismatch
        if (bcd_output !== expected_bcd) begin
            $display("%0t\t%0d\t%0d\t\t%0d\t\tMISMATCH", $time, test_binary, expected_bcd, bcd_output);
            errors = errors + 1; // Increment error counter
        end else begin
            $display("%0t\t%0d\t%0d\t\t%0d\t\tPASS", $time, test_binary, expected_bcd, bcd_output);
        end
    end
end

// Final simulation summary messages as requested
final begin
    $display("\n-------------------------------------------------");
    $display("Hint: Total mismatched samples is %1d out of %1d samples", errors, clocks);
    $display("Simulation finished at %0d ps", $time);
    $display("Mismatches: %1d in %1d samples", errors, clocks);
end

// VCD dump for waveform viewing
initial begin
    $dumpfile("binary_to_bcd.vcd");
    $dumpvars(0, tb);
end

// A simple clock for VCD dumping (optional but good practice)
reg vcd_clk;
initial vcd_clk = 0;
always #5 vcd_clk = ~vcd_clk;

endmodule