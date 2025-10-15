module mux2to1(input wire in1, input wire in2, input wire select, output wire out);
    assign out = (select) ? in2 : in1;
endmodule
module mux4to1(input [1:0] sel, input [3:0] in, output reg out);
    wire mux0_out, mux1_out;

    mux2to1 mux0 (.in1(in[0]), .in2(in[1]), .select(sel[0]), .out(mux0_out));
    mux2to1 mux1 (.in1(in[2]), .in2(in[3]), .select(sel[0]), .out(mux1_out));
    
    always @(*) begin
        case (sel[1])
            1'b0: out = mux0_out;
            1'b1: out = mux1_out;
        endcase
    end
endmodule
module mux8to1(input [2:0] sel, input [7:0] in, output reg out);
    wire mux0_out, mux1_out;

    mux4to1 mux0 (.sel(sel[1:0]), .in(in[3:0]), .out(mux0_out));
    mux4to1 mux1 (.sel(sel[1:0]), .in(in[7:4]), .out(mux1_out));
    
    always @(*) begin
        case (sel[2])
            1'b0: out = mux0_out;
            1'b1: out = mux1_out;
        endcase
    end
endmodule
