`timescale 1ns/1ps

module tb;

    // DUT params/signals
    localparam WIDTH = 16;
    reg                   clk;
    reg                   rst_n;
    reg                   enable;
    reg  [WIDTH-1:0]      period;
    reg  [WIDTH-1:0]      duty;
    wire                  pwm_out;
    wire                  tick;

    // Instantiate DUT
    top_module #(.WIDTH(WIDTH)) top_module1 (
        .clk(clk),
        .rst_n(rst_n),
        .enable(enable),
        .period(period),
        .duty(duty),
        .pwm_out(pwm_out),
        .tick(tick)
    );

    // Clock gen
    initial clk = 1'b0;
    always #5 clk = ~clk;

    // Utility: wait for N ticks (start-of-period markers)
    task wait_ticks;
        input integer n;
        integer i;
    begin
        for (i = 0; i < n; i = i + 1) begin
            @(posedge clk);
            while (tick !== 1'b1) @(posedge clk);
            // consume the tick cycle
            @(posedge clk);
        end
    end
    endtask

    // Measure one full PWM period: counts of high/low
    task measure_one_period;
        output integer highs;
        output integer lows;
        integer count;
    begin
        highs = 0;
        lows  = 0;

        // Wait for start-of-period
        @(posedge clk);
        while (tick !== 1'b1) @(posedge clk);
        // Consume this start cycle; now measure 'period' cycles
        count = 0;
        @(posedge clk);
        while (count < period) begin
            if (pwm_out === 1'b1) highs = highs + 1;
            else lows = lows + 1;
            count = count + 1;
            @(posedge clk);
        end
    end
    endtask

    // Check helper with tolerance (0 for exact)
    task check_ratio;
        input integer exp_highs;
        input integer meas_highs;
        input integer tol;
        input [127:0] label;
        integer diff;
    begin
        diff = (meas_highs > exp_highs) ? (meas_highs - exp_highs) : (exp_highs - meas_highs);
        if (diff <= tol) begin
            $display("[PASS] %0s: expected highs=%0d, measured=%0d (tol=%0d)", label, exp_highs, meas_highs, tol);
        end else begin
            $display("[FAIL] %0s: expected highs=%0d, measured=%0d (tol=%0d)", label, exp_highs, meas_highs, tol);
            $fatal(1);
        end
    end
    endtask

    // Stimulus
    integer highs, lows;

    initial begin
        // VCD
        $dumpfile("pwm.vcd");
        $dumpvars(0, tb);

        // Reset
        rst_n  = 1'b0;
        enable = 1'b0;
        period = 16'd100; // 100-cycle period
        duty   = 16'd0;

        repeat (5) @(posedge clk);
        rst_n  = 1'b1;
        @(posedge clk);

        // Enable DUT
        enable = 1'b1;

        // Test 0% duty
        duty = 16'd0;
        wait_ticks(2);
        measure_one_period(highs, lows);
        check_ratio(0, highs, 0, "duty=0%");

        // Test 25% duty (25 highs out of 100)
        duty = 16'd25;
        wait_ticks(2);
        measure_one_period(highs, lows);
        check_ratio(25, highs, 0, "duty=25%");

        // Test 50% duty
        duty = 16'd50;
        wait_ticks(2);
        measure_one_period(highs, lows);
        check_ratio(50, highs, 0, "duty=50%");

        // Test 75% duty
        duty = 16'd75;
        wait_ticks(2);
        measure_one_period(highs, lows);
        check_ratio(75, highs, 0, "duty=75%");

        // Test 100% duty (clamped if duty > period)
        duty = 16'd200; // > period, should clamp to 100
        wait_ticks(2);
        measure_one_period(highs, lows);
        check_ratio(100, highs, 0, "duty>=period (100%)");

        // Change period and re-check e.g. 1/3 ~ 33 cycles of 99
        period = 16'd99;
        duty   = 16'd33;
        wait_ticks(2);
        measure_one_period(highs, lows);
        check_ratio(33, highs, 0, "period=99, duty=33 (~33.3%)");

        $display("All PWM tests completed successfully!");
        $finish;
    end

endmodule

