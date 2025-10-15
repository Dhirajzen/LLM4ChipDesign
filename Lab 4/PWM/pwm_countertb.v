`timescale 1ns/1ps

module tb;
  // Parameters
  localparam WIDTH = 16;

  // DUT I/O
  reg                   clk;
  reg                   rst_n;
  reg                   enable;
  reg  [WIDTH-1:0]      period;
  wire [WIDTH-1:0]      count;
  wire                  tick;

  // Instantiate DUT
  pwm_counter #(.WIDTH(WIDTH)) dut (
    .clk(clk),
    .rst_n(rst_n),
    .enable(enable),
    .period(period),
    .count(count),
    .tick(tick)
  );

  // 10 ns clock
  initial clk = 1'b0;
  always #5 clk = ~clk;

  integer errors;

  // Check that when count == period-1, next cycle wraps to 0 and tick==1
  task check_wrap;
    input integer per;
    integer cycles;
    begin
      period = per[WIDTH-1:0];
      enable = 1'b1;

      // Let it run long enough to see several wraps
      cycles = 0;
      while (cycles < (3*per + 5)) begin
        @(posedge clk);
        // On the cycle AFTER period-1 we expect wrap + tick
        if (count == period - 1) begin
          @(posedge clk);
          if (count !== 0 || tick !== 1'b1) begin
            $display("[FAIL] wrap behavior incorrect: count=%0d tick=%0b (expected count=0,tick=1) at time %0t", count, tick, $time);
            errors = errors + 1;
          end
        end else begin
          // Normally tick must be 0
          if (tick !== 1'b0) begin
            $display("[FAIL] tick asserted unexpectedly (count=%0d) at time %0t", count, $time);
            errors = errors + 1;
          end
        end
        cycles = cycles + 1;
      end
    end
  endtask

  initial begin
    errors = 0;

    // Wave dump
    $dumpfile("pwm_counter_tb.vcd");
    $dumpvars(0, tb);

    // Reset
    rst_n  = 1'b0;
    enable = 1'b0;
    period = 16'd10;
    repeat (3) @(posedge clk);
    rst_n  = 1'b1;
    @(posedge clk);

    // After reset, count should start at 0 and tick==0
    if (count !== 0) begin
      $display("[FAIL] count not zero after reset release: count=%0d", count);
      errors = errors + 1;
    end
    if (tick !== 1'b0) begin
      $display("[FAIL] tick not zero after reset release: tick=%0b", tick);
      errors = errors + 1;
    end

    // Hold test: when enable=0, count must hold, tick=0
    enable = 1'b0;
    repeat (5) @(posedge clk);
    if (tick !== 1'b0) begin
      $display("[FAIL] tick high while enable=0");
      errors = errors + 1;
    end
    // Run test at period=10 then period=7
    enable = 1'b1;
    check_wrap(10);
    check_wrap(7);

    if (errors == 0) begin
      $display("All tests passed!");
      $display("passed!");
    end else begin
      $display("Total mismatches: %0d", errors);
    end
    $finish;
  end
endmodule
