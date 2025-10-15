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
