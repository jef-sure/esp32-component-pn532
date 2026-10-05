# Changelog

## v 0.6.1 - 2026-10-05

- **MIFARE Classic emulation on ISO14443-4 cards (SAK `0x28`/`0x38`) is usable as Classic** (`pn532-14443.c`, `pn532.c`). With the PN532's automatic RATS such a card is activated as ISO-DEP and refuses MIFARE commands. Like the NXP reference stack in its MIFARE mode, `pn532_14443_select_by_uid()` now re-lists a Classic-subtype card that has SAK bit `0x20` with automatic RATS switched off (SetParameters `0x04`); the next poll switches it back on (`0x14`). `pn532_init()` / `pn532_recover()` write SetParameters `0x14` once, since a chip without a reset pin keeps its parameters across an MCU restart. New state field `pn532_t.auto_rats_off`. To open the ISO-DEP side of such a card instead, set `subtype` to `PN532_MIFARE_DESFIRE` in your copy of the `pn532_uid_t` before selecting (README, "Cards with both MIFARE Classic and ISO-DEP").
- `pn532_mifare_block_read()` accepts only the 16-byte READ answer (a 4-byte answer was tolerated but would have left 12 bytes of the NDEF scan buffer unset).
- NDEF parsing rejects a TNF-unknown (`0x05`) record that carries a type, as NDEF 1.0 and Android do.

## v 0.6.0 - 2026-10-05

- **InDataExchange/InCommunicateThru MI continuations no longer re-send the RF payload** (`pn532.c`). UM0701-02 §7.3.5 continuation requests carry only the target number (InDataExchange) or nothing (InCommunicateThru); re-sending the original data forwarded the APDU/command to the card a second time. The mock now captures per-round request parameters, and the MI regression tests assert the continuation shape.
- Type 2 NDEF capacity now derives from the capability container instead of physical page counts (`pn532-ndef.c`). `CC[2] × 8` bytes is the NDEF data-area size, which excludes the lock/configuration pages the old NTAG213/215/216 page counts (45/135/231) walked into.
- Type 4 NDEF reads chunk by `MLe - 2` (`pn532-ndef.c`). MLe already counts data bytes only, so `Le = MLe` is legal; the two bytes of headroom are for cards that size MLe to their whole R-APDU buffer.
- `pn532_14443_4_read_binary()` rejects offsets above `0x7FFF` instead of silently wrapping them (short EF identifier mode masks bit 15 in P1) and fails with the required size in `*got` instead of silently truncating a response that exceeds the caller's buffer. The `pn532.h` contract documents both.
- Poll setup/release failures with a healthy transport now surface as `PN532_POLL_PROTOCOL_ERROR` instead of `PN532_POLL_TRANSPORT_ERROR` (`pn532-14443.c`), so applications following the README recovery guidance no longer run `pn532_recover()` against a chip that answered fine. The sample application counts only transport errors toward recovery and resets the counter on timeouts, quiet-field polls, and protocol errors.
- Public APIs reject NULL device pointers and out-of-range MIFARE block numbers: `pn532_execute_command()`, `pn532_reset()`, `pn532_in_data_exchange()`, `pn532_mifare_block_read()`/`_write()` (block numbers outside 0..255 previously wrapped through `uint8_t`, sending 256 as block 0).
- NDEF URI identifier `0x07` decodes to `ftp://anonymous:anonymous@` (`pn532-ndef.c`). The placeholder `"******"` never matched the 26-byte abbreviation configured for encoding, so the prefix could not round-trip.
- NDEF parsing enforces TNF structural rules (`pn532-ndef.c`): the reserved TNF `0x07` is rejected, and TNF-empty records carrying a type, ID, or payload fail instead of parsing.
- **IRQ mode: a queued ACK edge no longer ends the response wait early** (`pn532.c`). When the ACK had already pulled P70_IRQ low before the readiness pre-check, its edge stayed in the queue and the following response wait returned at once while the chip was still busy: SPI read garbage and sent a NACK mid-command, I2C survived only commands shorter than its 40 ms read retries. A queued edge is now only a hint to re-check the line; the wait also polls the bus every 10 ms, so the documented bus fallback works while the IRQ line is not driven.
- **NDEF record bounds checks no longer wrap on 32-bit targets** (`pn532-ndef.c`). `pos + payload_len > in_len` overflowed `size_t`; the 9-byte message `81 01 FF FF FF FF 54 00 00` parsed as a Text record with a 4 GiB payload. Type, ID, and payload lengths are now compared against the remaining bytes.
- **NDEF URI identifier codes follow NFC Forum URI RTD 1.0, table 3** (`pn532-ndef.c`). Codes `0x0B`..`0x1B` held non-standard prefixes (`smsto:`, `sms:`, `mms:`, `geo:`, `magnet:?`, ...) and `0x1C`..`0x23` were missing, so foreign tags decoded wrongly (`0x13` is `urn:`, not `geo:`) and abbreviated URIs written by this driver read wrongly elsewhere. Encoding now picks the longest matching standard prefix from the same table; the hand-kept length list is gone, which also fixes `ftp://ftp.` (length 9 instead of 10 produced `ftp://ftp..host` and matched `ftp://ftpserver`). **Tags written by earlier versions with `abbreviate=true` and one of the non-standard prefixes decode differently now.**
- Polling expects an ATS after every target whose SAK has the ISO14443-4 bit (`0x20`) (`pn532-14443.c`). SAK `0x28`, `0x38`, and `0x60` were treated as ATS-less, so a second target behind such a card was parsed from the middle of the ATS. A last entry without ATS (automatic RATS switched off) is accepted.
- `pn532_uid_t.atqa` keeps the SENS_RES bytes in the order the PN532 reports them (MIFARE Classic 1K is `0x0004`, previously `0x0400`).
- `pn532_14443_4_select_file()` selects files by identifier with `P2=0x0C` as Type 4 Tag mapping 2.0 requires, and retries once with the previous `P2=0x00` when the card refuses that. Selection by AID is unchanged.
- After a framing or MIFARE authentication error (`0x13`/`0x14`) the cached target number is marked stale (`pn532_t.tg_stale`): `pn532_14443_select_by_uid()` and the NDEF helpers then re-list the card instead of sending a bare InSelect to a card that fell back to IDLE, so the fallback keys of the MIFARE Classic NDEF reader get a live card.
- `pn532.h` and `pn532-mifare.h` are wrapped in `extern "C"` for C++ callers.
- `pn532_i2c_init()` / `pn532_i2c_attach()` use `PN532_I2C_DEFAULT_CLOCK_HZ` (100 kHz) for a zero clock instead of failing; the IRQ and reset pins are set up with `gpio_config()` so pads that default to another function work; `pn532_get_firmware_version()`, `pn532_set_rf_field()`, `pn532_set_rf_on()`/`_off()` reject a NULL device.
- Documentation: `pn532_14443_4_transceive()` states the PN532's own 262-byte InDataExchange limit next to the driver's 267-byte frame limit.
- Documentation: the README quick start iterates `uids[0..uids_count-1]` as promised, and `pn532.h` describes the `pn532_uids_array_t` trailing-UID allocation (`uids_count` entries) instead of calling `uids[1]` a flexible array.

## v 0.5.4 - 2026-10-01

- SPI: the status byte is now compared with `0x01` exactly instead of testing only bit 0. UM0701-02 §6.2.5 allows only `0x00`/`0x01`; a disconnected or stuck-high MISO read as `0xFF` and looked permanently ready, so every command failed on a garbage ACK and the abort drain ran its full guard (~0.7 s per command at 1 MHz). It now fails on the ACK timeout as a transport error.
- SPI: an invalid status byte is logged once when the line goes bad (`NSS n: invalid status 0x.., MISO not driven ...`) and once when it recovers, so a dead or miswired reader is identified by its NSS pin instead of only by repeated ACK timeouts.
- The post-abort drain is capped at 8 reads instead of 280. Each read takes a full 280-byte frame, so one or two reads cover any real leftover response.

## v 0.5.3 - 2026-10-01

- SPI: the wake-up pulse in `pn532_spi_init()` / `pn532_spi_attach()` left NSS low until the device's first transaction. With two readers on one bus (both transports created before the first `pn532_init()`), reader B stayed selected during the whole init of reader A and could drive MISO in parallel. NSS now returns high right after the pulse; `pn532_reset()` still sends its own wake pulse and every transaction drives CS itself.
- SPI: the CS `pre_cb`/`post_cb` callbacks are now `IRAM_ATTR` and toggle NSS with `gpio_ll_set_level()` instead of the flash-resident `gpio_set_level()`. They run from the SPI ISR, so on a bus initialised by the application with `ESP_INTR_FLAG_IRAM` (reachable through `pn532_spi_attach()`) a flash operation could previously crash them.
- Polling and `pn532_14443_select_by_uid()` used a 64-byte `InListPassiveTarget` response buffer. Two ISO-DEP targets with long ATS could exceed it, and the "buffer too small" failure surfaced as `PN532_POLL_TRANSPORT_ERROR`, which the README recovery guidance turns into `pn532_recover()` calls. The buffers now hold the largest PN532 frame (`PN532_MAX_BUF_SIZE`); added a two-long-ATS regression test.

## v 0.5.2 - 2026-10-01

- Documentation only: the README install command now references an existing registry version (0.5.0 was withdrawn).

## v 0.5.1 - 2026-10-01

- Removed the dead MIFARE Classic branch (auth/sector callbacks, trailer skipping) from the flat NDEF reader, which is only used for Type 2 tags; Classic NDEF is read sector by sector via MAD. No behaviour change.

## v 0.5.0 - 2026-10-01

New API:

- `pn532_spi_attach()` and `pn532_i2c_attach()` attach a PN532 to a bus already created by the application (the I2C variant needs ESP-IDF >= 5.4). The bus stays owned by the caller; destroying the transport removes only the PN532 device.
- `pn532_uart_set_baud_rate()` switches the PN532 and the host UART together via `SetSerialBaudRate` (0x10), committing the switch with the host ACK required by UM0701-02. Rate codes come from an explicit rate-to-code table.
- `PN532_SPI_DEFAULT_CLOCK_HZ` (1 MHz), used when the SPI clock argument is non-positive (a warning is logged).

Link reliability and recovery:

- Corrupted response frames (bad length/data checksum, broken header or postamble, truncated UART frame) are now requested again with the UM0701-02 NACK frame (up to 2 times) instead of failing the command. The command itself is not re-executed, so non-idempotent operations (writes, RF exchanges) are safe.
- Transports can re-negotiate a silent link through a generic `resync` hook. HSU uses it to probe all nine PN532 rates (including 1.288 Mbaud, BR `0x08` per UM0701-02 §7.2.8) when the module does not answer at the configured one; `pn532_init()` logs the rate it actually found.
- With a wired IRQ pin, readiness is taken from the P70_IRQ level (low = response pending, UM0701-02 §6.3) before falling back to the bus check. On HSU this replaces the "at least 6 bytes buffered" heuristic with the chip's own signal.
- `pn532_recover()` now verifies the link first (with transport resync) and only then re-applies SAM/retry configuration, so a module that power-cycled back to its default HSU rate is recovered instead of failing at SAM configuration.

Transport fixes:

- SPI: a host bus initialised by the driver is now freed when the last PN532 on it is destroyed (previously it was never freed). Buses initialised by the application are never freed by the driver.
- I2C: fixed the wake-up added in v0.2.0 never reaching the bus. It used a zero-length `i2c_master_transmit()`, which ESP-IDF rejects with `ESP_ERR_INVALID_ARG` before any bus activity, so a PN532 in Power Down was not woken by `pn532_reset()`/`pn532_recover()`. Wake-up now uses `i2c_master_probe()` (START + own address + STOP), which is what the PN532 wake-up block recognises (PN532/C1 §8.3.2.6).
- I2C: retries probe the status byte before reading data, and a NACK from a busy PN532 is retried like a `0x00` status instead of failing immediately. NACKs while polling readiness are logged at debug level.
- HSU: responses are read by the length in the frame header instead of waiting for 20 ms of line silence; malformed headers fall back to the previous idle-based read.
- Ready polling checks the bus every RTOS tick against a wall-clock deadline instead of in fixed 10 ms steps.
- SPI: the 1-byte status read uses `spi_device_polling_transmit()`, avoiding interrupt and task-switch latency on every poll.
- I2C: `scl_wait_us` is now 10 ms (was the IDF default of ~2 ms). Leaving Power Down the PN532 stretches SCL for T_osc_start (UM0701-02 §7.2.11); this is an upper bound, not a delay, and stays below the classic ESP32 hardware limit (~13 ms at 80 MHz).
- Corrected UM0701-02 section references in source comments (InDeselect §7.3.10, InRelease §7.3.11, InSelect §7.3.12, wake-up conditions §7.2.11).
- `pn532_deinit()` resets the IRQ and RST GPIOs after removing the ISR handler, so a subsequent `pn532_init()` on the same pins starts clean.

Tests: added coverage for NACK retransmission, init/recover link resync and baud-change rejection on non-UART transports; the mock now answers `GetFirmwareVersion` with a real 4-byte payload, and Unity array asserts with compound literals were fixed to compile.

## v 0.4.5 - 2026-09-27

- Fixed `pn532_get_general_status()` decoding the wrong response format. The invented "logical target / ISO14443-4 / CID / NAD bitmask" fields do not exist in the raw GetGeneralStatus reply; the code was actually reading `Tg1`, `BrRx1/BrTx1`, and `Type1 + Tg2` as masks (a confusion with the higher-level TAL `PN53X_GET_STATUS` abstraction, which passes the raw buffer through undecoded). The struct now models the real UM0701-02 layout `Err Field NbTg [Tg BrRx BrTx Type]{NbTg} SAMstatus` with per-target entries and the trailing SAM status byte; truncated target lists are rejected. The mock regression test now feeds a realistic chip-format frame instead of a self-consistent one.

## v 0.4.4 - 2026-09-27

- Fixed the stale-handle class in `pn532_in_deselect()`: the `0x27` (target not known) branch closed only `session_opened` while keeping `inListedTag`, so a later `pn532_14443_4_transceive()` would retry the auto-`InSelect` against a target the chip no longer knows — the same stale-target wedge already fixed for the RF-timeout path. The `0x27` branch now clears both fields; the normal `0x00` path still keeps the target listed for reactivation. Regression coverage extended to assert the cleared handle, and the README lifecycle wording now scopes the listed-target guarantee to the success path.

## v 0.4.3 - 2026-09-27

- Fixed targeted `InListPassiveTarget` activation for cascaded UIDs (UM0701-02 §7.3.5): the InitiatorData now carries the cascade tag `0x88` in front of every cascade level except the last, instead of passing the raw 7/10-byte UID. Single-level 4-byte UIDs are unchanged, and the caller-owned `pn532_uid_t` is no longer mutated while building the frame.
- Resized the command buffer from `params[2 + 10]` to `params[2 + 12]`: the old buffer could not physically hold a 10-byte UID plus its two cascade tags (12 data bytes), which would have been a silent stack overflow once the tags were inserted.
- Fixed `pn532_in_select()` and `pn532_in_deselect()` treating status `0x27` as success via a misleading `PN532_STATUS_ALREADY_SELECTED` constant. Per UM0701-02, `0x27` means "target not known" and is an error for both commands; only `0x00` is success now. Added regression coverage for the rejected status.
- Fixed `pn532_release_target()` ignoring the `InRelease` status byte: transport success was treated as command success even when the PN532 reported an error, and local target state was cleared anyway. The status is now checked like InSelect/InDeselect; on a real error the local state is left untouched, while `0x27` (target not known) clears the state and succeeds like the NXP TAMA reference so poll loops cannot wedge.
- Fixed a deadlock after an RF-timeout `InDataExchange`: the forced RF field-off makes the PN532 drop every listed target, but the stale `inListedTag` survived and made every later auto-`InSelect` fail with `0x27` forever. The target handle is now cleared together with the field state.
- Added mock-based regression coverage verifying the emitted InitiatorData for 7- and 10-byte UIDs.

## v 0.4.2 - 2026-09-27

- Documented the ISO-DEP lifecycle explicitly: poll, select, repeated APDU exchange, and release/deselect, including automatic `InSelect` when a listed target remains but its session is closed.
- Made `pn532_apdu_get_status()` a regular exported function and aligned all APDU helper declarations, definitions, tests, and README examples on the `esp_err_t` contract.
- Reused the common response APDU parser in the Type 4 SELECT FILE and READ BINARY helpers; encoded short `Le = 0` now requests 256 bytes.
- Added regression coverage for ISO-DEP session reuse, Type 4 helper delegation through `InDataExchange`, APDU frame-size limits, parser edge cases, and response-builder capacity checks.

## v 0.4.1 - 2026-09-27

- Finalized the transport-independent ISO 7816-4 utility API with `esp_err_t` parser/builder results, zero-copy command and response data, decoded short `Le = 0` semantics, and `pn532_apdu_get_status()`.
- Moved APDU parsing and response construction into the standalone `pn532-apdu.c` module with no hardware access or dynamic allocation.
- Removed the redundant provisional ISO-DEP convenience wrappers; `pn532_14443_4_transceive()` remains the single low-level ISO-DEP exchange API.
- Expanded unit coverage for all short APDU cases, malformed and extended APDUs, NULL arguments, response status words, output capacity, and PN532 host-frame size boundaries.
- Updated the README to show the existing `poll -> select -> pn532_14443_4_transceive() -> release` lifecycle with stateless APDU parsing.

## v 0.4.0 - 2026-09-27

- Added a zero-copy ISO 7816-4 short APDU API: command parsing for cases 1, 2S, 3S, and 4S, response parsing, response construction, and common status-word constants.
- Added provisional ISO-DEP convenience wrappers over the existing selected-target state and PN532 `InDataExchange` path.
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
