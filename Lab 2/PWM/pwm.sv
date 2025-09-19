// Generate a synthesizable Verilog module for a parameterizable PWM generator. It should be in verilog not in system verilog. Write the code compatible with iverilog

// Specifications:
// - Module name: top_module
// - Parameters:
//     WIDTH = 16 (default)
// - Inputs:
//     clk      : clock
//     rst_n    : active-low synchronous reset
//     enable   : when high, PWM runs; when low, output forced low and counter holds
//     period   : total cycle length (WIDTH bits, >0)
//     duty     : duty cycle (WIDTH bits, 0..period, clamp if > period)
// - Outputs:
//     pwm_out  : high for 'duty' cycles out of each 'period'
//     tick     : single-cycle pulse when counter resets (start of period)

// Behavior:
// - Counter increments each clk when enabled, resets to 0 after reaching (period-1).
// - pwm_out is high while counter < duty.
// - tick asserted for one cycle at start of each PWM period.
// - On reset, counter clears to 0, outputs cleared.

// Constraints:
// - Use synchronous reset logic.

module top_module #(
    parameter WIDTH = 16
) (
    input  wire                clk,
    input  wire                rst_n,
    input  wire                enable,
    input  wire [WIDTH-1:0]    period,
    input  wire [WIDTH-1:0]    duty,
    output reg                 pwm_out,
    output reg                 tick
);


endmodule

