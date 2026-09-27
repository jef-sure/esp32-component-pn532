# Changelog

## v 0.4.2 - 2026-09-27

- Documented the ISO-DEP lifecycle explicitly: poll, select, repeated APDU exchange, and release/deselect, including automatic `InSelect` when a listed target remains but its session is closed.
- Made `pn532_apdu_get_status()` a regular exported function and aligned all APDU helper declarations, definitions, tests, and README examples on the `esp_err_t` contract.
- Reused the common response APDU parser in the Type 4 SELECT FILE and READ BINARY helpers; encoded short `Le = 0` now requests 256 bytes.
- Added regression coverage for ISO-DEP session reuse, Type 4 helper delegation through `InDataExchange`, APDU frame-size limits, parser edge cases, and response-builder capacity checks.

## v 0.4.1 - 2026-09-27

- Finalized the transport-independent ISO 7816-4 utility API with `esp_err_t` parser/builder results, zero-copy command and response data, decoded short `Le = 0` semantics, and `pn532_apdu_get_status()`.
- Moved APDU parsing and response construction into the standalone `pn532-apdu.c` module with no hardware access or dynamic allocation.
- Removed the redundant `pn532_iso_dep_connect()`, `pn532_iso_dep_transceive()`, and `pn532_iso_dep_disconnect()` wrappers; `pn532_14443_4_transceive()` remains the single low-level ISO-DEP exchange API.
- Expanded unit coverage for all short APDU cases, malformed and extended APDUs, NULL arguments, response status words, output capacity, and PN532 host-frame size boundaries.
- Updated the README to show the existing `poll -> select -> pn532_14443_4_transceive() -> release` lifecycle with stateless APDU parsing.

## v 0.4.0 - 2026-09-27

- Added a zero-copy ISO 7816-4 short APDU API: command parsing for cases 1, 2S, 3S, and 4S, response parsing, response construction, and common status-word constants.
- Added `pn532_iso_dep_connect()`, `pn532_iso_dep_transceive()`, and `pn532_iso_dep_disconnect()` as thin convenience wrappers over the existing selected-target state and PN532 `InDataExchange` path.
- Documented Type 4 NDEF reading, raw APDU exchange with status-word handling, and APDU inspection before transfer.
- Correctly convert the ISO-DEP exchange timeout from FreeRTOS ticks to milliseconds before passing it to the existing PN532 timeout path.

## v 0.3.2 - 2026-09-27

- Documentation only: expanded the README with I2C and UART setup snippets, a complete MIFARE Classic read cycle (poll, select, key-A auth, data blocks, release), a Type 4 ISO-DEP example (NDEF AID, file select, READ BINARY), a full NTAG URI write cycle, `GetGeneralStatus` and `InCommunicateThru` usage examples, a troubleshooting section, and the ESP Component Registry badge.

## v 0.3.1 - 2026-09-27

- Stripped the NAD byte from `InDataExchange` and `InCommunicateThru` responses when the status byte carries NAD (0x80), matching `phTalTama_Transceive()`. The driver never negotiates NAD, but a target sending it anyway no longer shifts the caller's payload by one byte. A NAD flag with an empty payload is rejected as a protocol error.
- `pn532_in_communicate_thru()` now fails fast with "no target selected" instead of burning an RF timeout when no target is listed.

## v 0.3.0 - 2026-09-27

- Added `pn532_in_communicate_thru()` exposing the InCommunicateThru command (0x42): raw ISO14443 bit exchange with the currently activated target, without the DEP/MIFARE wrapping of InDataExchange. MI-chained raw replies are drained and concatenated; the API bump marks the new public raw-exchange surface.

## v 0.2.2 - 2026-09-27

- Added `pn532_get_general_status()` exposing the GetGeneralStatus command (0x04): decoded error code, external RF field presence, detected target count, and the logical target / ISO14443-4 activation / CID / NAD bitmasks, mirroring the NXP TAL `PHHALNFC_IOCTL_PN53X_GET_STATUS` diagnostics probe.

## v 0.2.1 - 2026-09-27

- Implemented MI (More Information) chaining in `pn532_in_data_exchange()`, mirroring `phTalTama_Transceive()`: when the status byte carries MI (0x40) the exchange is re-issued and payload fragments are concatenated until a non-MI status terminates the chain. Chains that never terminate are cut off after 64 rounds and drop the session so the next exchange re-selects the target.
- MI-chained responses previously returned only the first fragment as a successful payload, silently losing the remainder of long responses.

## v 0.2.0 - 2026-09-27

- Split the ACK wait from the response wait in `pn532_execute_command()`: the ACK phase now gets its own short budget (`pn532->ack_timeout_ms`, default 50 ms, NXP TAMA reference uses 10 ms) so a wedged chip fails fast instead of blocking 2 × 500 ms per command. ACK timeouts report `PN532_COMMAND_STATUS_ACK_TIMEOUT` and surface as `PN532_POLL_TRANSPORT_ERROR`; response timeouts keep `PN532_POLL_TIMEOUT`. Tunable via `pn532_set_ack_timeout()`.
- Made the post-abort drain read the full PN532 buffer in a loop instead of a single 16-byte read, preventing an aborted two-card `InListPassiveTarget` response (~65 bytes) from shifting the next frame into `invalid frame header`.
- Moved the RF settle delay into the component: `pn532_set_rf_off()` now waits `pn532->rf_settle_delay_ms` (default 20 ms, measured on hardware with a static card and a 250 ms poll cycle) so a HALT-state card powers down before the next poll. Tunable via `pn532_set_rf_settle_delay()`; applications no longer need their own post-RF-off delay. The previous hard-coded 5 ms delay in the poll prepare path was removed.
- Added `pn532_recover()`: full software re-initialisation (abort, reset, SAM/retry reconfig, firmware check, RF off) on the existing bus, replacing manual `pn532_deinit()` + re-init cycles after repeated transport failures.
- Added `pn532_deselect_target()` issuing `InDeselect` (0x44) for a soft HALT that keeps the target listed inside the PN532.
- Gave every transport a `wake()` callback mirroring the NXP `phTalTama_WakeUp` role: HSU re-sends the `0x55 0x55` preamble and I2C issues a START-condition probe (SPI keeps its NSS-edge wake). `pn532_reset()` and `pn532_recover()` now wake a sleeping chip on all buses, not only at bus creation.
- Aligned `InDataExchange` status handling with the NXP TAMA reference: error codes are checked through `ERROR_MASK` (0x3F), so MI (0x40) chained data and NAD (0x80) responses from T=CL cards are no longer misread as errors; after an RF_TIMEOUT status the driver now also switches the RF field off with a best-effort RFConfiguration, matching `phTalTama_Transceive`.
- Stopped multi-sector MIFARE Classic NDEF reads at the first failed block instead of concatenating later sectors across a missing data block.
- Added `ndef_parse_message()` and NDEF chunk reassembly: physical records with `CF` are exposed as one logical record with a contiguous payload, while malformed chunk sequences are rejected.
- Updated the two-reader shared-SPI example to drop the manual post-RF-off delay and demonstrate `pn532_recover()` on repeated transport failures.

## v 0.1.1 - 2026-09-26

- Made UID polling return listed targets without automatically issuing `InSelect`; callers explicitly select a target before reading it.
- Preserved each listed target's `Tg` so explicit selection can issue `InSelect` without repeating `InListPassiveTarget`.
- Avoided repeated `spi_bus_initialize()` calls when attaching PN532 devices with separate NSS pins to an existing SPI master bus.
- Documented separate `poll -> RF off` and `poll -> select/read -> release -> RF off` lifecycles.

## v 0.1.0 - 2026-09-26

- Added `pn532_14443_get_all_uids_ex()` with an optional polling-status output while preserving `pn532_14443_get_all_uids()`.
- Exposed `pn532_release_target()` and made successful RF-off invalidate the active target/session.
- Aligned polling and timeout abort behavior with the NXP TAMA reference.
- Documented and tested sequential PN532 polling on a shared SPI bus with distinct NSS pins.

## v 0.0.3 - 2026-04-29

### Convert examples/simple to ESP-IDF project layout

Replaced the old example-component `CMakeLists.txt` with a project-level `CMakeLists.txt` and added `examples/simple/main/CMakeLists.txt`.

### Refresh documentation for the new example structure

Updated the root README and `examples/simple/README.md` to describe the project layout and direct-build dependency setup.

## v 0.0.2 - 2026-04-29

### Add optional IRQ-backed ready notifications

When a valid IRQ GPIO is passed to `pn532_init()`, the driver can use PN532 ready interrupts while waiting for ACK and response frames.

### Add retry tuning helpers to the public API

Exposed `pn532_set_max_retries()` and `pn532_set_passive_activation_retries()` in `pn532.h`.

### Add raw PN532 command execution helper

Exposed `pn532_execute_command()` for commands that do not yet have a dedicated typed helper.

### Restructure the simple SPI example source tree

Moved the sample source to `examples/simple/main/main.c` and updated the example component `CMakeLists.txt` to match.

### Split simple example documentation out of the root README

Moved sample-specific wiring, integration notes, and related usage details into `examples/simple/README.md`.

### Add dedicated README for examples/simple

Documented the sample folder layout, default SPI wiring, integration options, and normal `idf.py` workflow.

## v 0.0.1 - 2026-04-28

Initial import from another project
