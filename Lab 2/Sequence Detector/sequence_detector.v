/*
Output ONLY synthesizable Verilog-2001 code — no markdown, no comments, no explanations, and nothing outside the module.

Write a module named top_module with:

Inputs: clk, reset_n, data[2:0]

Output: sequence_found

Implement a finite state machine (FSM) with states S0–S7 encoded as 4-bit localparams. The FSM updates on posedge clk and uses an active-low asynchronous reset: when reset_n==0, go to S0.

State transitions:

S0 → S1 if data==3'b001, else S0

S1 → S2 if data==3'b101, else S0

S2 → S3 if data==3'b110, else S0

S3 → S4 if data==3'b000, else S0

S4 → S5 if data==3'b110, else S0

S5 → S6 if data==3'b110, else S0

S6 → S7 if data==3'b011, else S0

S7 → S0 unconditionally

Combinational output:
sequence_found is 1 only when state==S7 AND data==3'b101.

Return only the complete Verilog-2001 module ending with endmodule. Do NOT generate a testbench.
*/