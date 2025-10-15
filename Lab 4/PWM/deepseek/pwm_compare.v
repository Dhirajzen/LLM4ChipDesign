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
        end else begin
            tick <= 0;
            if (enable) begin
                if (count == period - 1) begin
                    count <= 0;
                    tick <= 1;
                end else begin
                    count <= count + 1;
                end
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
module pwm_generator #(parameter WIDTH = 8) (
    input clk,
    input rst_n,
    input enable,
    input [WIDTH-1:0] period,
    input [WIDTH-1:0] duty,
    output pwm_out
);
    wire [WIDTH-1:0] count;

    pwm_counter #(.WIDTH(WIDTH)) counter (
        .clk(clk),
        .rst_n(rst_n),
        .enable(enable),
        .period(period),
        .count(count),
        .tick()
    );

    pwm_compare #(.WIDTH(WIDTH)) compare (
        .count(count),
        .duty(duty),
        .period(period),
        .pwm_out(pwm_out)
    );

endmodule
