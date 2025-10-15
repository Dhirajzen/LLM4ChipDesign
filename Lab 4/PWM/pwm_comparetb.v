`timescale 1ns/1ps

module tb;
  localparam WIDTH = 16;

  reg  [WIDTH-1:0] count;
  reg  [WIDTH-1:0] duty;
  reg  [WIDTH-1:0] period;
  wire             pwm_out;

  integer errors;
  integer i;
  integer effduty;

  // DUT is purely combinational
  pwm_compare #(.WIDTH(WIDTH)) dut (
    .count(count),
    .duty(duty),
    .period(period),
    .pwm_out(pwm_out)
  );

  task sweep_case;
    input integer per;
    input integer dty;
    begin
      period  = per[WIDTH-1:0];
      duty    = dty[WIDTH-1:0];
      effduty = (dty > per) ? per : dty;

      // sweep count from 0 .. per-1
      for (i = 0; i < per; i = i + 1) begin
        count = i[WIDTH-1:0];
        #1; // let signals settle
        if (pwm_out !== (count < effduty)) begin
          $display("[FAIL] per=%0d duty=%0d eff=%0d count=%0d pwm_out=%0b exp=%0b",
                    per, dty, effduty, i, pwm_out, (count < effduty));
          errors = errors + 1;
        end
      end
    end
  endtask

  initial begin
    errors = 0;

    $dumpfile("pwm_compare_tb.vcd");
    $dumpvars(0, tb);

    // Basic cases
    sweep_case(100, 0);    // 0%
    sweep_case(100, 25);   // 25%
    sweep_case(100, 50);   // 50%
    sweep_case(100, 75);   // 75%
    sweep_case(100, 200);  // >period -> clamp to 100%
    sweep_case(99,  33);   // ~33%

    if (errors == 0) begin
      $display("All tests passed!");
      $display("passed!");
    end else begin
      $display("Total mismatches: %0d", errors);
    end
    $finish;
  end
endmodule
