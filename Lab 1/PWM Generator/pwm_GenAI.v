module pwm #(
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

    reg [WIDTH-1:0] cnt;

    always @(posedge clk) begin
        if (!rst_n) begin
            cnt    <= {WIDTH{1'b0}};
            pwm_out <= 1'b0;
            tick    <= 1'b0;
        end else begin
            if (!enable) begin
                cnt    <= cnt;
                pwm_out <= 1'b0;
                tick    <= 1'b0;
            end else begin
                if (cnt == period - 1'b1) begin
                    cnt  <= {WIDTH{1'b0}};
                    tick <= 1'b1;
                end else begin
                    cnt  <= cnt + 1'b1;
                    tick <= 1'b0;
                end
                pwm_out <= (cnt < duty);
            end
        end
    end

endmodule