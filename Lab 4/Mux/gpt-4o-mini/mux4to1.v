module mux2to1(input wire in1, input wire in2, input wire select, output wire out);
    assign out = (select) ? in2 : in1;
endmodule
module mux4to1(input [1:0] sel, input [3:0] in, output reg out);
    wire out0, out1;

    // Instantiate two 2-to-1 multiplexers
    mux2to1 mux0(.in1(in[0]), .in2(in[1]), .select(sel[0]), .out(out0));
    mux2to1 mux1(.in1(in[2]), .in2(in[3]), .select(sel[0]), .out(out1));
    
    // Select between the outputs of the two 2-to-1 multiplexers
    always @(*) begin
        case (sel[1])
            1'b0: out = out0;
            1'b1: out = out1;
        endcase
    end
endmodule
