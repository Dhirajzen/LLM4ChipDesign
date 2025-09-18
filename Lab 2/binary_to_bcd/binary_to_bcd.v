// Create a Verilog model binary_to_bcd_converter for a binary to binary-coded-decimal converter. It must meet the following specifications:
// 	- Inputs:
// 		- Binary input (5-bits)
// 	- Outputs:
// 		- BCD (8-bits: 4-bits for the 10's place and 4-bits for the 1's place)

// How would I write a design that meets these specifications?

module top_module (
    input  [4:0] binary_input,  // 5-bit binary input (0-31)
    output [7:0] bcd_output     // 8-bit BCD output: [7:4]=tens, [3:0]=units
);

// Insert your code here

endmodule