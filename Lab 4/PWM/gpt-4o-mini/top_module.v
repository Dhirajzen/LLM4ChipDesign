module pwm_counter #(parameter WIDTH = 8) (
    input clk, 
    input rst_n, 
    input enable, 
    input [WIDTH-1:0] period, 
    output reg [WIDTH-1:0] count, 
    output reg tick
);
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            count <= 0;
            tick <= 0;
        end else if (enable) begin
            if (count == period - 1) begin
                count <= 0;
                tick <= 1;
            end else begin
                count <= count + 1;
                tick <= 0;
            end
        end
    end
endmodule
module pwm_compare #(parameter WIDTH = 8) (
    input [WIDTH-1:0] count, 
    input [WIDTH-1:0] duty, 
    input [WIDTH-1:0] period, 
    output wire pwm_out
);
    assign pwm_out = (count < (duty < period ? duty : period));
endmodule
module top_module #(parameter WIDTH = 8) (
    input clk, 
    input rst_n, 
    input enable, 
    input [WIDTH-1:0] period, 
    input [WIDTH-1:0] duty, 
    output wire pwm_out, 
    output wire tick // Added tick output for connecting to testbench
);
    wire [WIDTH-1:0] count;

    pwm_counter #(WIDTH) counter_inst (
        .clk(clk), 
        .rst_n(rst_n), 
        .enable(enable), 
        .period(period), 
        .count(count), 
        .tick(tick) // Connection for tick output
    );

    pwm_compare #(WIDTH) compare_inst (
        .count(count), 
        .duty(duty), 
        .period(period), 
        .pwm_out(pwm_out)
    );
endmodule
