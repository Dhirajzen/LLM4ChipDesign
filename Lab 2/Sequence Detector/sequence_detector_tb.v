`timescale 1ns/1ps

module tb;
    reg clk;
    reg reset_n;
    reg [2:0] data;
    wire sequence_found;

    integer errors;
    integer clocks;

    // Instantiate DUT
    top_module dut (
        .clk(clk),
        .reset_n(reset_n),
        .data(data),
        .sequence_found(sequence_found)
    );

    // Clock generation
    always #5 clk = ~clk;

    // Stimulus task
    task apply_stimulus;
        input [2:0] data_value;
        input integer delay_cycles;
        begin
            data <= data_value;
            repeat (delay_cycles) @(posedge clk);
        end
    endtask

    // Checker task
    task check_output;
        input integer cycle;
        input expected_value;
        begin
            clocks = clocks + 1;
            if (sequence_found !== expected_value) begin
                errors = errors + 1;
                $display("Error: Cycle %0d, Expected: %b, Got: %b", cycle, expected_value, sequence_found);
            end
        end
    endtask

    initial begin
        clk      = 1'b0;
        reset_n  = 1'b0;
        data     = 3'b000;
        errors   = 0;
        clocks   = 0;

        // Apply reset
        @(posedge clk);
        reset_n = 1'b1;

        // Test case: Correct sequence
        apply_stimulus(3'b001, 1); check_output(1, 1'b0);
        apply_stimulus(3'b101, 1); check_output(2, 1'b0);
        apply_stimulus(3'b110, 1); check_output(3, 1'b0);
        apply_stimulus(3'b000, 1); check_output(4, 1'b0);
        apply_stimulus(3'b110, 1); check_output(5, 1'b0);
        apply_stimulus(3'b110, 1); check_output(6, 1'b0);
        apply_stimulus(3'b011, 1); check_output(7, 1'b0);
        apply_stimulus(3'b101, 1); check_output(8, 1'b1);

        // Test case: Incorrect sequence
        apply_stimulus(3'b001, 1); check_output(9, 1'b0);
        apply_stimulus(3'b101, 1); check_output(10, 1'b0);
        apply_stimulus(3'b010, 1); check_output(11, 1'b0);
        apply_stimulus(3'b000, 1); check_output(12, 1'b0);

        // Summary
        $display("Hint: Total mismatched samples is %1d out of %1d samples", errors, clocks);
        $display("Simulation finished at %0d ps", $time);
        $display("Mismatches: %1d in %1d samples", errors, clocks);

        $finish;
    end
endmodule
