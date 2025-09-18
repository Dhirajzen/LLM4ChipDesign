module pwm #(
    parameter WIDTH = 16
) (
    input  wire               clk,
    input  wire               rst_n,    // active-low synchronous reset
    input  wire               enable,
    input  wire [WIDTH-1:0]   period,
    input  wire [WIDTH-1:0]   duty,
    output reg                pwm_out,
    output reg                tick
);

    reg [WIDTH-1:0] ctr;
    wire [WIDTH-1:0] duty_clamped;

    // Clamp duty to period (if duty > period, treat as duty = period)
    assign duty_clamped = (duty > period) ? period : duty;

    always @(posedge clk) begin
        if (!rst_n) begin
            ctr     <= {WIDTH{1'b0}};
            pwm_out <= 1'b0;
            tick    <= 1'b0;
        end else if (enable) begin
            // Period tick at ctr==0 (start of cycle)
            tick <= (ctr == {WIDTH{1'b0}}) ? 1'b1 : 1'b0;

            // Output high when ctr < duty
            pwm_out <= (ctr < duty_clamped);

            // Counter update
            if (ctr + 1 >= period) begin
                ctr <= {WIDTH{1'b0}};
            end else begin
                ctr <= ctr + 1;
            end
        end else begin
            // Disabled: hold counter, force output low, no tick
            tick    <= 1'b0;
            pwm_out <= 1'b0;
        end
    end

endmodule