# Changelog

## v 0.8.2 - 2026-11-03

Fixes from an audit of 0.8.1 and its follow-up, checked against NxpNfcRdLib phalTop (MIFARE Classic, Type 2 and Type 4 NDEF detection), libnfc 1.8 and mfoc (MIFARE Classic authentication errors), UM0701-02 table 13 and §7.3.1, and the ESP-IDF 5.5.4 and 6.1 GPIO headers. Host tests only; nothing here was run on hardware.

Fixes:

- **MIFARE Classic: a card lost at a directory key is a read error, not a card without NDEF** (`pn532-ndef.c`). The MAD key and the default key failed alike whether the card turned them down or could not be selected or did not answer, and both became `PN532_NDEF_ERR_NO_NDEF`: a card that left the field, or an RF error at that moment, gave a definite "no NDEF", and `pn532_ndef_read_card_auto()` did not try again. A key now counts as refused only when the chip reports the MIFARE authentication error `14h` (UM0701-02 table 13). A card that cannot be selected, times out (`01h`), or answers with an RF error (CRC, parity, framing, `0Bh`, `13h`) is `PN532_NDEF_ERR_READ_FAILED`, and the read is repeated once from a new listing; the second key is not tried on it. The same holds for the MAD2 sector of a 4K card. libnfc draws the same line (`EMFAUTH` against its RF transmission errors), and mfoc, which tries keys on PN53x readers, accepts only `14h` for a wrong key and stops on anything else. NxpNfcRdLib phalTop and ESPHome take any failed MAD authentication for a tag without NDEF.
- **MIFARE Classic: NDEF sectors that turn both public keys down are `PN532_NDEF_ERR_ACCESS_DENIED`** (`pn532-ndef.c`). They were `PN532_NDEF_ERR_READ_FAILED`, so the whole read ran a second time to the same end, and the example skipped its block dump. NxpNfcRdLib phalTop takes such a tag as misconfigured, without a retry either. A card lost at that point is still a read error.
- **Type 4: a SELECT that fails without a status word is a read error** (`pn532-ndef.c`, `pn532-14443.c`). Only the PN532 statuses that drop or mark the target (`01h`, `0Bh`, `13h`, `14h`) were told apart; any other one, a CRC, parity or framing error or `27h`, left the session open and was taken for the card refusing the SELECT: `PN532_NDEF_ERR_NO_NDEF` after one exchange. The reader now uses what `pn532_14443_4_select()` already knew, whether the card answered with a status word (new internal `pn532_14443_4_select_file_ex()`); everything else is `PN532_NDEF_ERR_READ_FAILED` and is repeated once.
- **Type 2: the version and read access of the capability container are checked** (`pn532-ndef.c`). A major version other than 1 is `PN532_NDEF_ERR_UNSUPPORTED` on read and write, as in NxpNfcRdLib phalTop, which reads only version 1.x; the layout of another major version may differ. A read access other than `0h` (high nibble of byte 3: RFU or proprietary) is `PN532_NDEF_ERR_ACCESS_DENIED`, as for a Type 4 NDEF file. Both used to be read like a version 1.0 tag with free access.
- **MIFARE Classic: a failed authentication marks the target for a new listing** (`pn532-14443.c`). After a refused key (`14h`) the card is in HALT and the target was already marked; after an RF error half way it is out of the active state as well, but the target stayed selected, so the next key or `pn532_14443_select_by_uid()` sent a bare InSelect, which does not wake the card. `pn532_14443_authenticate()` now marks the target after every failed exchange; libnfc's nfc-mfclassic and mfoc re-select after every failed key too.
- New field `pn532_t.last_target_status`: the error code of the last InDataExchange or InCommunicateThru the chip answered (`0xFF` when it gave none), as libnfc keeps its `last_status_byte`. It tells a refused key from an RF error.
- **MIFARE Classic: the general purpose byte of the first NDEF sector is checked** (`pn532-ndef.c`), as NxpNfcRdLib phalTop does after the directory: a mapping major version above 1 is `PN532_NDEF_ERR_UNSUPPORTED`, a read access other than `00b` (AN1304) `PN532_NDEF_ERR_ACCESS_DENIED`. The read costs one more READ, of that sector's trailer. Both used to be read like a version 1.0 sector with free access.
- **MIFARE value operations with a NULL device** (`pn532-mifare.c`): `pn532_mifare_increment()`, `pn532_mifare_decrement()`, `pn532_mifare_restore()` and `pn532_mifare_transfer()` read `pn532->timeout_ms` before the call that checks for NULL, and crashed. They return false now.
- **`pn532_init()` checks its pins** (`pn532.c`). An IRQ number that is not a GPIO, an RST number that is not an output GPIO, or a pin `gpio_config()` refuses now makes it return NULL before the bus is used; the numbers went into the 64-bit `gpio_config()` mask unchecked, and its result was ignored. A failed `gpio_set_intr_type()` falls back to polling the bus, as a failed ISR service or handler already did.
- **SPI: an NSS that is not an output GPIO is refused** (`pn532-bus-spi.c`). `pn532_spi_init()` and `pn532_spi_attach()` put `GPIO_NUM_NC` into the `gpio_config()` mask as `1ULL << -1`, which is undefined. Both now return NULL before the host is touched.
- `pn532_delay_ms()`: a delay of one RTOS tick or more sleeps to the first tick at or after its end (`pn532.c`), instead of sleeping whole ticks and spinning for the rest. The 20 ms RF settle delay and the 250 ms poll pause of the example spun about 5 ms per call on average at `CONFIG_FREERTOS_HZ=100`; they may now end up to one tick late, never early. A delay shorter than a tick (the 2 to 5 ms transport pauses) is a busy wait as before.
- `pn532_release_target()` forgets the UID behind the freed target number, and with no target left marks the field off, as the chip switches it off (UM0701-02 §7.3.11). A later `pn532_14443_select_by_uid()` of that card lists it again at once; it used to try an InSelect first, which the chip refused with 27h and the driver logged as an error.

Changes:

- Less stack (`pn532.c`): `InDataExchange` writes the target number and the caller's data into the frame without first copying them into a 280-byte buffer, and `pn532_rf_configuration()` no longer keeps 280 bytes for at most 11 (UM0701-02 §7.3.1, item 0Ah). Measured with `-fstack-usage` on ESP-IDF 5.5.4 for the esp32 at `-Og`, `pn532_in_data_exchange()` takes 384 bytes instead of 656, and the deepest path, a Type 4 NDEF read down to the SPI transport, about 1.15 KB of driver frames instead of 1.4 KB. The README's "about 850 bytes", an estimate from buffer sizes, is replaced by the measured figures.
- Example: each key and key type of the MIFARE Classic dump costs one authentication, and the card is listed again only after a refusal. It authenticated twice per pair with a listing in between, the second time with the key just refused, and sent the next key to a card in IDLE.

Documentation:

- README: a paragraph on reading two cards at once. Docs from the audit of 0.8.1: after an ACK or response timeout the abort clears the state of `pn532_release_target()`, it is not kept; readers may run in separate tasks, and readers whose fields overlap take turns.
- README and `pn532-ndef.h` list the new results of `pn532_ndef_read_card_auto()` and `pn532_ndef_write_to_selected_card()`, and when a read is repeated; `pn532.h` and the README the pin checks of `pn532_init()`, `pn532_spi_init()` and `pn532_spi_attach()`, what `pn532_14443_authenticate()` leaves after a failure, and the settle delay that may end a tick late. The example README says when the example dumps blocks.

Tests:

- The simulated card can leave the field at a given exchange, a simulated MIFARE Classic checks keys against its sector trailers, and a simulated Type 4 tag can refuse the NDEF application.
- New cases for each fix above, among them one that sends `02h`, `0Bh`, `13h` and `14h` to the MAD key; the NDEF ones fail on the previous sources, and the SPI one stops there under UBSan (`shift exponent -1 is negative`). 91 host tests under ASan/UBSan. The example compiles on ESP-IDF 5.5.4 and 6.1 for the esp32, the test app on 5.5.4.

## v 0.8.1 - 2026-11-02

Fixes from an audit of 0.8.0, checked against NxpNfcRdLib phalTop (Type 2 NDEF position and sectors, Type 4 application and status words, MIFARE Classic directory), UM0701-02 §7.3.11 and the NXP FRI InRelease path, and the ESP-IDF 5.5.4 and 6.1 sources. Host tests only; nothing here was run on hardware.

Fixes:

- **SPI: a PN532 joins a host the application has just initialised** (`pn532-bus-spi.c`). ESP-IDF answers `spi_bus_get_max_transaction_len()` only after the first `spi_bus_add_device()` on a host, so `spi_bus_initialize()` followed by `pn532_spi_attach()`, the setup the README documents, returned NULL since `pn532_spi_attach()` appeared in 0.5.0, and `pn532_spi_init()` on such a host tried to initialise it a second time. The transaction size is now checked once the PN532 is on the host; a host that cannot carry a frame is refused as before and keeps no device.
- **Type 2: a write that readers would not find is refused** (`pn532-ndef.c`). Readers take the first NDEF TLV behind the control TLVs, where NxpNfcRdLib also writes it. A `start_block` beyond them on a factory NTAG left the empty NDEF TLV `03 00 FE` in front of the message: the call returned OK and every reader saw an empty tag. The bytes in between must now be NULL TLVs or other TLVs that end at `start_block` (lock and reserved bytes left out, as readers do); otherwise the call is `PN532_NDEF_ERR_INVALID_PARAM` before a page is written.
- **An InRelease answered with an error status frees the target all the same** (`pn532.c`, `pn532-14443.c`). UM0701-02 §7.3.11 frees the logical number "in all the cases", and the NXP FRI ignores the status. A status other than `0x00` and `0x27`, which a card that left the field can cause, kept the target and stopped the poll, so every later poll stopped on it again until `pn532_recover()`. `pn532_release_target()` still returns false for it, but clears the state, and the poll goes on.
- **Type 2: nothing beyond page 255 is written or read** (`pn532-ndef.c`). Those pages, the second sector of an NTAG I2C 2K, need SECTOR_SELECT, which NxpNfcRdLib phalTop sends and this driver does not. A long write hid the old message and then failed at page 256, leaving an empty tag; it is now `PN532_NDEF_ERR_UNSUPPORTED` before anything is written. A message that continues there reads as `PN532_NDEF_ERR_UNSUPPORTED` instead of a read error with a retry.
- **MIFARE Classic: a failed READ of the directory is a read error** (`pn532-ndef.c`), as in NxpNfcRdLib: after the MAD key was accepted it means that the card left or fell back to IDLE, so `pn532_ndef_read_card_auto()` now repeats the read from a new listing instead of reporting no NDEF. The fallback that assumed MAD v1 when the general purpose byte could not be read is gone: it read on from a card in IDLE and could not succeed. A MAD2 sector no key opens is still no NDEF.
- The Ultralight/NTAG variant probes run only when the card passed in is the selected one (`pn532-14443.c`); with a session open on another card they asked that card and could drop its session and MIFARE authentication.
- GET_VERSION: the storage sizes of the NTAG213/215/216 name an NTAG only with product type 04h (`pn532-14443.c`), as the sizes of the NTAG210/212 already did; another Ultralight family member of that size stays an Ultralight.
- A SetParameters without an answer leaves the automatic RATS state unknown (`pn532.c`), so the next request sends it whatever it asks for; the chip may have applied the flags. Until then `pn532_14443_select_by_uid()` lists the card again instead of reusing its handle. New field `pn532_t.auto_rats_unknown`.
- UART: the wait for a frame to leave grows with its length at the current baud (`pn532-bus-uart.c`), as the read budget does. At 9600 baud the fixed 100 ms ran out for about 96 bytes or more while the frame still went out, and the caller got a transport error for a command the chip ran.
- `pn532_14443_4_transceive()` fails at once for a target that needs a new listing (`pn532-14443.c`), instead of sending an InSelect that does not wake it and waiting out up to 1.5 s.
- I2C: the status byte is read into the transport's buffer in internal RAM (`pn532-bus-i2c.c`). With `CONFIG_I2C_ISR_IRAM_SAFE` ESP-IDF refuses a read buffer outside internal RAM, which a task stack in PSRAM would be, and the reader looked dead.

Documentation:

- `pn532_ndef_extract_text()` and `pn532_ndef_extract_uri()` leave the buffer as it was on an error; `pn532_set_passive_activation_retries()` sets the ATR and PSL retries to the chip defaults; `pn532_mifare_block_read()` needs a 16-byte buffer.
- `timeout_ms` is the one `pn532_t` field the application sets; the driver has no locking, one `pn532_t` belongs to one task at a time.
- Type 4: only the NDEF application of mapping 2.0 and later is selected, as in NxpNfcRdLib; a mapping 1.0 tag is no NDEF. The header did not say so.
- The README said a deselect or release refused with a status leaves the state untouched; a deselect closes the session, a release frees the target.
- README and headers follow the fixes above: the Type 2 write rules and page limit, the Classic read retry, the Type 4 AID, `pn532_spi_attach()` right after `spi_bus_initialize()`, the stale target of `pn532_14443_4_transceive()`. With an IRQ pin the bus status is still read every 10 ms as a fallback; the card type comes from the SAK, not from ATQA and SAK; `pn532_in_select()` is internal and no longer named in `pn532.h`.

Checked and kept:

- ISO 7816 warnings `62xx` / `63xx` fail an APDU and drop its data, as NxpNfcRdLib phalTop does: it takes only `9000` and `9100` for success, `6282` (end of file) included among the errors.
- UART at 9600 baud: a wait for readiness needs 6 buffered bytes (6 ms), and the reads that follow have a budget that grows with the frame at the current baud, so the 50 ms ACK budget covers a resent response and an ACK read after the IRQ line.

Tests:

- `host_test` builds the SPI transport against a stand-in for the ESP-IDF master driver in which, as in ESP-IDF, the transaction size is known only after the first device.
- New cases for each fix above but the UART and I2C ones; ten of them fail on the 0.8.0 sources. 81 host tests under ASan/UBSan. Compiled with the example on ESP-IDF 5.5.4 and 6.1 for esp32, and for esp32s3 on 6.1.

## v 0.8.0 - 2026-11-02

Breaking changes:

- **`pn532_ndef_extract_text()` takes the size of `lang_buf`** (`pn532-ndef.c`): the new argument `lang_buf_len` follows `lang_buf`. The card sets the length of the language code, up to 63 bytes, and every earlier version copied it into a buffer of unknown size. The README example passed `char lang[8]`, so a Text record with a language code of 8 bytes or more overflowed the caller's stack; reproduced under ASan, and code that copied the example has this bug until it moves to this version. The code is now truncated to fit and always NUL-terminated, as in `pn532_ndef_extract_uri()`; the text pointer and length do not depend on it. A call in the old form no longer compiles: add `sizeof(lang)` after the buffer, or `0` after `NULL`.

Documentation:

- The README example uses `char lang[64]` and says that the host tests build the I2C transport.

Tests:

- A Text record with a 63-byte language code against a short buffer, a buffer of 64 bytes, a zero size and no buffer.

## v 0.7.7 - 2026-11-01

I2C fixes. Not run on a PN532 over I2C: the test boards have their readers on SPI. The ESP-IDF behaviour below was read in the sources of 5.5.4, 5.5.5, 6.0.3 and 6.1, and measured on a JC4827 board with a GT911 touch controller on 6.1; the PN532 transport was run on the host against a stand-in for the I2C master driver.

Fixes:

- **I2C: `pn532_i2c_init()` creates a blocking bus** (`pn532-bus-i2c.c`). `trans_queue_depth = 1`, there since the first version, puts an ESP-IDF bus into its asynchronous mode. `i2c_master_receive()` then returned `ESP_OK` after about 46 µs, before the byte arrived, also for an address nobody answered (`ESP_ERR_INVALID_RESPONSE` and about 230 µs on a blocking bus). The readiness check looked at its still empty status variable, and the interrupt wrote the byte to that stack variable later, after the function had returned. By the code a PN532 could practically never get through `pn532_init()` on this path, and every poll wrote one byte to stack memory the check no longer owned; the warning ESP-IDF prints for this mode also calls it incompatible with `i2c_master_probe()`, the I2C wake-up. `pn532_i2c_attach()` was not affected on a bus without a queue, which the README example creates; the requirement is now documented.
- I2C: ready is bit 0 of the status byte, the other bits are rfu (UM0701-02 §6.2.4); the whole byte was compared with `0x01`.

Kept on purpose:

- I2C reads the status byte alone and the frame in a new read, as Adafruit_PN532, its CircuitPython driver and ESPHome do. UM0701-02 §6.2.4 and AN10449 §2.4.2 ask for one read without a STOP (Fig 31/32 of the manual draw two accesses), but reports from real chips say a STOP right after the status byte keeps the frame: a 2016 test on a Raspberry Pi and go-pn532 on a Raspberry Pi 5 with a logic analyzer. The 0.7.7 bus runs this path here for the first time; if a chip did lose the frame, `pn532_init()` would fail instead of returning bad data.

Tests:

- `host_test` builds the I2C transport against a stand-in for the ESP-IDF driver that behaves like the real one on a bus with a queue.

## v 0.7.6 - 2026-11-01

Packaging only, no code changes.

- The `files` section of the manifest is now an explicit list: the component archive holds the sources, the headers, the example, the README, the change log and the license. `host_test/`, `test_apps/`, `.clang-format` and `.gitignore` stay in the repository.
- The README says that the tests are not part of the component archive.

## v 0.7.5 - 2026-10-27

Fixes from an audit of 0.7.4, checked against the NXP FRISDK reference, NxpNfcRdLib (phalTop Type 2 and Type 4, phNfcLib) and the PN532/C1 datasheet. Run on an ESP32 with two PN532 on separate SPI hosts, one task per reader and both at the same time, with NTAG213, MIFARE Classic 1K and DESFire cards. Two readers on one shared SPI host have run 0.7.4 only.

Behaviour changes:

- **SPI: NSS is driven from the calling task, not from the SPI interrupt** (`pn532-bus-spi.c`). The `pre_cb` / `post_cb` callbacks run in the SPI ISR for interrupt transactions, so every frame transfer spent the 100 µs NSS setup wait there. The driver now holds the bus with `spi_device_acquire_bus()` while it drives NSS as a GPIO around the transaction; the setup time stays 100 µs, and a second device on the host cannot be selected meanwhile.
- **Type 4: the NDEF Tag Application Select carries Le = 00h** (`pn532-14443.c`), as the NFC Forum Type 4 Tag specification and NxpNfcRdLib write it; strict ISO 7816 applets refuse the form without Le. A select by file identifier has no Le. The answer of a select may take a full short R-APDU (258 bytes).
- **Type 2 NDEF read leaves out the lock and reserved bytes** (`pn532-ndef.c`) that Lock Control and Memory Control TLVs place inside the data area, as NxpNfcRdLib phalTop does, so a message continues behind them. A control TLV layout the scan cannot follow is read as before. The scan starts from the 12 data-area bytes the capability container READ already returns: the write needs one READ less on a factory NTAG21x, the read none extra.
- `pn532_14443_select_by_uid()`: a refused InSelect of a cached target number falls back to a new listing instead of returning a handle that fails the same way on every retry.
- `pn532_in_communicate_thru()`: statuses `0x01`, `0x0B`, `0x13` and `0x14` mark the target stale and close the session, as `pn532_in_data_exchange()` does; the field stays on.
- `pn532_spi_init()` refuses a host initialised by the application whose transactions are shorter than a PN532 frame, as `pn532_spi_attach()` already did.
- SAK `0x11` is `PN532_MIFARE_PLUS_4K` with 256 blocks (MIFARE Plus 4K at security level 2, NxpNfcRdLib phNfcLib); it was `PN532_MIFARE_PLUS_2K` with 128. SAK `0x10` stays `PN532_MIFARE_PLUS_2K`.

Fixes:

- `pn532_in_data_exchange()`: the RF-off after an RF timeout no longer overwrites `last_command_status` with the status of that clean-up command.
- `pn532_reset()` documents that a hardware reset drops the SAM, retry and SetParameters configuration until `pn532_recover()` writes it again.

Measured on the hardware named above:

- Without a card, in four runs: init, error frame, PowerDown and wake-up, 200 commands per clock from 500 kHz to 5 MHz without a failure on either reader, and 40 polls per reader with both readers polling at the same time. A status read takes 150 to 190 µs, 100 µs of them the NSS setup.
- An NTAG213 lying on a reader: type from GET_VERSION, NDEF read before and after provoked errors, write guards, and 70 of 70 poll / select / read cycles. An NTAG213 on one reader and a Classic 1K on the other, both readers at once: 70 of 70 cycles on each.
- A DESFire without an NDEF application refuses the Select with Le every time, and the read returns `PN532_NDEF_ERR_NO_NDEF`. Some cards are not listed in part of the polls (the DESFire about one poll in eleven, on either reader); the polling code did not change in this version.

Tests: 69 host tests under ASan/UBSan (new: InSelect fallback, InCommunicateThru statuses, reserved bytes of a Memory Control TLV, the IRQ wait path through the bus fallback, MIFARE Plus SAKs; the Type 4 select test checks the Le byte).

## v 0.7.4 - 2026-10-07

Fixes from a review of 0.7.3, checked against NxpNfcRdLib (phalTop Type 2 and Type 4). Run on the host tests only; the Type 2 write was not repeated on hardware.

Behaviour changes:

- **`pn532_ndef_read_card_auto()` does not read a card other than the one asked for** (`pn532-ndef.c`). With two cards in the field and a session left open on the first, a call for the second read the first one again. The helper now compares the UID behind the selected target with the requested one and selects the requested card first. A UID length other than 4, 7 or 10 is `PN532_NDEF_ERR_INVALID_PARAM`.
- **`pn532_ndef_write_to_selected_card()` keeps Lock Control and Memory Control TLVs** (`pn532-ndef.c`). The NDEF TLV is written behind the control TLVs at the start of the data area, as NxpNfcRdLib does. A factory NTAG213/215/216 has a 5-byte Lock Control TLV in page 4: the message now starts at byte 5 of the data area and has 5 bytes less; 0.7.3 overwrote the TLV. Lock or reserved bytes that a control TLV places inside the pages to write are `PN532_NDEF_ERR_UNSUPPORTED`, a control TLV with a wrong length field is `PN532_NDEF_ERR_PARSE_FAILED`. The helper reads the first one or two 16-byte windows of the data area before it writes.
- **A Type 2 tag without write access is not written**: capability container byte 3 other than `00` is the new result `PN532_NDEF_ERR_READ_ONLY` (-11).
- Type 4 NDEF read: a capability container with CCLEN below 15 or MLe below 000Fh is `PN532_NDEF_ERR_PARSE_FAILED`; an MLe of 0 to 2 was replaced by 248 before.
- `pn532_14443_authenticate()` returns false for a Classic card without an exchange when `blockno` is outside 0..255, the command is neither Key A nor Key B, or the UID length is not 4, 7 or 10; the block number used to be cut to 8 bits.
- A listed target with a UID length other than 4, 7 or 10 is a malformed listing (`PN532_POLL_PROTOCOL_ERROR`); such a card could not be selected afterwards.
- `pn532_ndef_make_mime_record()` and `pn532_ndef_make_external_record()` return false for `data == NULL` with a non-zero length; the record was built and refused later by the encoder.

Fixes:

- Frame and exchange length checks no longer rely on an addition that a length near `SIZE_MAX` wraps (`pn532_write_frame()`, `pn532_in_data_exchange()`, `pn532_in_communicate_thru()`).

Not changed: the review reported URI identifier `0x07` as `"******"`; the table holds `ftp://anonymous:anonymous@` since 0.6.0. The NDEF File Control TLV of a Type 4 tag is read at offset 7, where the specification and NxpNfcRdLib place it.

Tests: 64 host tests (new: session on another card, control TLVs and write access of Type 2 tags, argument and length checks).

## v 0.7.3 - 2026-10-07

Fixes on real hardware: an ESP32-P4 with two PN532 on one SPI host (no IRQ, no reset line), with NTAG213, Ultralight-compatible, MIFARE Classic 1K and ISO-DEP cards. The changes come from an audit of 0.7.2 against UM0701-02, the PN532/C1 datasheet and the ESP-IDF headers, and from what the hardware runs showed.

Behaviour changes:

- **`pn532_ndef_write_to_selected_card()` protects the pages that cannot be repaired** (`pn532-ndef.c`). `start_block` below 4 (UID, lock bytes, one-time programmable capability container) and a non-positive `max_blocks` are `PN532_NDEF_ERR_INVALID_PARAM`; `max_blocks <= 0` used to switch the capacity check off. The helper reads the capability container and keeps the write inside the data area it describes, so a `max_blocks` taken from `uid->blocks_count` no longer reaches the dynamic lock and configuration pages. A tag without a capability container is `PN532_NDEF_ERR_NO_NDEF`. A message longer than 65534 bytes is `PN532_NDEF_ERR_CARD_FULL`; its length was cut to 16 bits. `max_blocks` is documented: a number of pages counted from `start_block`.
- **`pn532_in_communicate_thru()` is one exchange** (`pn532.c`). InCommunicateThru does no chaining and its status byte is an error code only (UM0701-02 §7.3.9), so the MI bit no longer starts a continuation round (which sent an empty frame to the card) and the NAD bit no longer removes the first reply byte. The MI rounds of InDataExchange stay, documented as DEP-only; the reference in the comments is §7.3.8, not §7.3.5.
- **A command without an ACK is sent once more** (`pn532.c`), as UM0701-02 §6.2.2.1 asks: the chip has not taken a frame it did not acknowledge. A dead transport is now reported after two ACK budgets (100 ms by default).
- `pn532_ndef_encode_message()` returns 0 for records the parser of this driver refuses: an Empty record with a type, ID or payload, an Unknown record with a type, and the TNF values Unchanged and Reserved.
- `pn532_get_firmware_version()` returns 0 when the IC byte is not `0x32`.
- `pn532_spi_attach()` returns NULL for a host whose transactions are shorter than a PN532 frame (`max_transfer_sz` below `PN532_MAX_BUF_SIZE`, or a bus without DMA); the first read failed there before.
- SPI clocks above 5 MHz and I2C clocks above 400 kHz are lowered to these limits with a warning (`PN532_SPI_MAX_CLOCK_HZ`, `PN532_I2C_MAX_CLOCK_HZ`).

Fixes:

- **SPI: a busy PN532 answering status `0x08` is no longer reported as a line fault** (`pn532-bus-spi.c`). Bit 3 of the SPI status register is TR_FE, set when the host reads the FIFO empty (PN532/C1 §8.3.5.7), which every full-buffer read of a short frame does. Since 0.5.4 the driver took any byte but `0x00` / `0x01` for an undriven MISO and logged `invalid status 0x08, MISO not driven` as a warning about once per command; printing it more than doubled the time of a command (9 ms against 4 ms at 1 MHz). Ready is bit 0 again, as UM0701-02 §6.2.5 says and 0.4.5 did; a line fault is a set reserved bit (7..4 or 1), so `0xFF` from an open MISO still does not read as ready.
- Status `0x0B` (RF protocol error) of InDataExchange marks the target stale like `0x13` and `0x14`: an NTAG213 answered a refused READ with it, and the card then needs a new listing as well.
- **SPI builds on ESP-IDF 5.2 and 5.3** (`pn532-bus-spi.c`): `spi_bus_dma_memory_alloc()` exists from 5.4 on; older versions take the buffers from `heap_caps_malloc(MALLOC_CAP_DMA)`. Compiled here with 5.5.4 only.
- An error frame or an unexpected response code is `PN532_POLL_PROTOCOL_ERROR` at the polling layer (new internal status `PN532_COMMAND_STATUS_REJECTED`); it was `PN532_POLL_TRANSPORT_ERROR`, which the README answers with `pn532_recover()`.
- I2C: a command write the PN532 does not acknowledge is repeated up to three times, 2 ms apart (UM0701-02 §6.2.4); reads already did that.
- Type 4 NDEF: the second read attempt lists the card again when its target is stale (status `0x13` / `0x14`), as for Type 2 and MIFARE Classic.
- SPI wake-up: NSS stays low for 4 ms; 2 ms was exactly the maximum of T_osc_start, without margin. NSS is driven high before the pad becomes an output.
- `pn532_execute_command()` rejects `params == NULL` with a non-zero `params_len`; `pn532_ndef_parse_message()` sets `*out_msg` to NULL on every error.
- Comments: status `0x13` is "data format does not match", not a framing error; no response follows an abort, the drain covers a race; `br_rx` / `br_tx` have no 847 kbit/s code.

Measured on the hardware named above:

- The link is clean from 500 kHz to 5 MHz (no failed command in 200 per clock on both readers); a request for 8 MHz runs at 5 MHz.
- A command sent right after PowerDown is lost on one of the two modules while the chip wakes up; the repeat after the missing ACK delivers it every time. With the wake-up pulse of `pn532_reset()` no frame is lost.
- An unknown command gets the syntax error frame and `PN532_COMMAND_STATUS_REJECTED`; the next command works. The PN532 also answers an InDataExchange with an unknown MIFARE command byte that way, without sending it to the card.
- After InDeselect the next InDataExchange works without an InSelect on all four card types.
- After status `0x13` / `0x14` (refused READ, READ without authentication, wrong key) InSelect answers `0x00` but the next exchange fails; only a new InListPassiveTarget brings the card back, as the driver assumes.
- With a card lying still, 70 cycles of poll, select, NDEF read, release and RF off pass without a miss for an ISO-DEP card on either reader, an Ultralight-compatible tag, and two such tags in the field of one reader (about 160 ms per cycle for one card, 210 ms for two), back to back and with 250 ms between the cycles. The same runs with MxRtyPassiveActivation lowered from the driver's 5 to 2 missed listings now and then.
- A card in the field of both readers, which sit side by side, is listed and read by both in turn (30 of 30 cycles on each with 250 ms between the cycles).
- A target with a random UID (first byte `08`, a phone for example) gets a new UID with every activation, so it cannot be listed again by its UID after the field was switched off. The README has a section on such targets.

Tests and CI: 61 host tests (new: ACK repeat, error frame, argument and IC checks, Type 2 write limits with a simulated NTAG213, encoder rules, Type 4 re-listing, stale target after `0x0B`). `host_test/Makefile` accepts `UNITY_DIR` in place of `IDF_PATH`, and a GitHub workflow runs the host tests on push and pull request.

## v 0.7.2 - 2026-10-07

Fixes from an external review of 0.7.1.

- `pn532_uart_set_baud_rate()`: a device with `timeout_ms` set to 0 no longer waits without limit for the answer; 500 ms is used instead. The documented contract is corrected: after a failed exchange the module can be on either rate, because the host ACK of the abort procedure is the ACK that makes the PN532 switch (UM0701-02 §7.2.8, fig. 53) when its response was sent but lost on the line. The README said "still on the previous rate". `pn532_recover()` finds the module in both cases.
- `pn532_ndef_decode_smartposter()` applies the rules of the message parser to the nested message: a payload without Message End, with a second Message Begin, or with data after the last record returns 0 instead of the records decoded so far. Chunked nested records return 0 as well.
- MIFARE Classic NDEF: a failed read is repeated once from a freshly listed card, as for Type 2 and Type 4; a sector authentication re-lists a card whose target number is stale.
- Documentation: the README introduction no longer promises NDEF writing for MIFARE Classic and Type 4 (it exists for NTAG / Ultralight only); `pn532_recover()` in `pn532.h` lists its steps in the order the code runs them; new README section on task stack use; return value contracts of `pn532_ndef_encode_message()`, `pn532_ndef_extract_uri()` and `pn532_mifare_value_read()` spelled out; `PN532_MIFARE_PLUS_4K` and `PN532_NDEF_ERR_BUFFER_TOO_SMALL` marked as reserved; comments on the zero-timeout wait and on the SPI NSS setup time corrected.

## v 0.7.1 - 2026-10-07

Fixes from a check of 0.7.0 against UM0701-02, the NXP reader library (`phalTop`, `phacDiscLoop`) and the MIFARE Ultralight datasheets.

- `pn532_14443_detect_selected_card_type_and_capacity()` probes the Ultralight family only while a target session is open. InCommunicateThru talks to whatever card is active (UM0701-02 §7.3.9 leaves the selection to the host), so after a poll with two cards the probe could reach the other card. A card that is listed but not selected now gets the SAK result only.
- Type 4: a capability container with the Extended NDEF File Control TLV (`06`, mapping 3.x, files above 32 KB) is `PN532_NDEF_ERR_UNSUPPORTED`; it was `PN532_NDEF_ERR_PARSE_FAILED`. The mapping version is checked before the TLV.
- Documentation: the Type 4 chunk size is MLe − 2, at most 248 bytes (the README said 250); `pn532-ndef.c` no longer claims Type 1 support.

## v 0.7.0 - 2026-10-07

This release brings over what the PN5180 component gained in its 0.2.0 to 0.4.3 releases.

Breaking changes:

- **Every public NDEF name carries the component prefix.** Functions and types `ndef_*` are now `pn532_ndef_*` (for example `pn532_ndef_parse_message()`, `pn532_ndef_record_t`, `pn532_ndef_write_to_selected_card()`); constants `NDEF_*` are now `PN532_NDEF_*` (for example `PN532_NDEF_OK`, `PN532_NDEF_TNF_WELL_KNOWN`, `PN532_NDEF_RTD_URI`). The MIFARE command macros of `pn532-mifare.h` are `PN532_MIFARE_CMD_*` and `PN532_MIFARE_ULTRALIGHT_CMD_WRITE`. There are no compatibility aliases: add the prefix in application code. `pn532_ndef_read_card_auto()` keeps its name.
- `pn532_nfc_type_t` has two new values, `PN532_MIFARE_NTAG210` and `PN532_MIFARE_NTAG212`, placed before `PN532_MIFARE_NTAG213`, so the numeric values of the later subtypes changed.
- `pn532_ndef_result_t` has a new value, `PN532_NDEF_ERR_ACCESS_DENIED`.

Card identification:

- **`pn532_14443_detect_selected_card_type_and_capacity()` probes the Ultralight family** (`pn532-14443.c`). It was a wrapper around the SAK table, and `PN532_MIFARE_ULTRALIGHT_C` / `PN532_MIFARE_ULTRALIGHT_EV1` were never reported. For a selected SAK `0x00` card it now sends GET_VERSION through InCommunicateThru (Ultralight EV1, NTAG210/212/213/215/216, with the page count); a card without GET_VERSION is listed again and asked for an AUTHENTICATE (`1A`) challenge, which only an Ultralight C gives. After a refused probe `needs_reselect` is `true` and the card has to be selected again. Not yet checked against real cards.
- An SAK that is not in the table but has the ISO14443-4 bit (`0x20`) set, such as `0x60`, is reported as `PN532_MIFARE_DESFIRE` instead of `PN532_MIFARE_UNKNOWN`, so `pn532_ndef_read_card_auto()` takes the Type 4 path for it.
- The capability container of a Type 2 tag no longer replaces a subtype the card itself reported: an Ultralight C (CC size `0x12`) was renamed to NTAG213 by the NDEF reader.

NDEF reading (`pn532-ndef.c`):

- Type 2: a tag without the capability container magic (`E1`) or with an empty data area returns `PN532_NDEF_ERR_NO_NDEF` after reading page 3. The memory was scanned anyway before (60 pages for a zero size).
- Type 2: the last READ of the data area is cut at its end. The pages after it (lock and configuration pages, or page 0 after a wrap-around) were fed to the TLV search.
- MIFARE Classic: the CRC of the MIFARE Application Directory (MAD1 and MAD2) is checked; a directory with a wrong CRC is treated as absent (`PN532_NDEF_ERR_NO_NDEF`).
- Type 4: a read-protected NDEF file is `PN532_NDEF_ERR_ACCESS_DENIED`, a mapping version other than 1.x to 3.x is `PN532_NDEF_ERR_UNSUPPORTED`, and an NDEF length that does not fit the file is `PN532_NDEF_ERR_PARSE_FAILED` (was `PN532_NDEF_ERR_NO_NDEF`).

Other changes:

- `pn532_delay_ms()` is precise below an RTOS tick: whole ticks are slept and the remainder is a busy wait. Every delay was rounded up to tick boundaries before, so a 2 ms wake-up pause took up to 12 ms at `CONFIG_FREERTOS_HZ=100`. Delays shorter than a tick no longer yield to other tasks.
- **Host tests** in `host_test/`: the tests of `test_apps/polling` run on the host under AddressSanitizer, without hardware and without an ESP-IDF build: `make -C host_test test IDF_PATH=<esp-idf>`. The bus transports are not part of that build.
- The mock of the tests can put a simulated card behind the PN532 (Type 2, MIFARE Classic, Type 4); new tests cover the changes of this release.

## v 0.6.2 - 2026-10-06

- **SPI wake-up pulse is 2 ms at any tick rate** (`pn532-bus-spi.c`). `vTaskDelay(pdMS_TO_TICKS(2))` is zero ticks at `CONFIG_FREERTOS_HZ=100`, which left a microsecond NSS pulse without the T1 settle time of PN532/C1 §8.5.6. The pulse now waits on wall-clock time through `pn532_delay_ms()`.
- **SPI wake-up pulse holds the bus** (`pn532-bus-spi.c`). The pulse drives NSS outside a transaction; with a second reader on the same host polled from another task, both chips could be selected at once. `pn532_spi_init()` / `pn532_spi_attach()` and the wake-up after `pn532_reset()` now take the bus with `spi_device_acquire_bus()` for the pulse. Readers driven from one task were not affected.
- **`pn532_14443_select_by_uid()` no longer reuses a Tg that belongs to another card** (`pn532-14443.c`). The PN532 numbers targets from 1 on every InListPassiveTarget, so a `pn532_uid_t` kept from an earlier poll could carry the Tg of the card listed after it, and the bare InSelect opened that card instead. The driver keeps the UID behind each Tg of the latest listing (`pn532_t.listed_uid`, `listed_uid_len`) and takes the InSelect shortcut only when it matches; otherwise the card is re-listed by its UID.

## v 0.6.1 - 2026-10-05

- **MIFARE Classic emulation on ISO14443-4 cards (SAK `0x28`/`0x38`) is usable as Classic** (`pn532-14443.c`, `pn532.c`). With the PN532's automatic RATS such a card is activated as ISO-DEP and refuses MIFARE commands. Like the NXP reference stack in its MIFARE mode, `pn532_14443_select_by_uid()` now re-lists a Classic-subtype card that has SAK bit `0x20` with automatic RATS switched off (SetParameters `0x04`); the next poll switches it back on (`0x14`). `pn532_init()` / `pn532_recover()` write SetParameters `0x14` once, since a chip without a reset pin keeps its parameters across an MCU restart. New state field `pn532_t.auto_rats_off`. To open the ISO-DEP side of such a card instead, set `subtype` to `PN532_MIFARE_DESFIRE` in your copy of the `pn532_uid_t` before selecting (README, "Cards with both MIFARE Classic and ISO-DEP").
- `pn532_mifare_block_read()` accepts only the 16-byte READ answer (a 4-byte answer was tolerated but would have left 12 bytes of the NDEF scan buffer unset).
- NDEF parsing rejects a TNF-unknown (`0x05`) record that carries a type, as NDEF 1.0 and Android do.

## v 0.6.0 - 2026-10-05

- **InDataExchange/InCommunicateThru MI continuations no longer re-send the RF payload** (`pn532.c`). UM0701-02 §7.3.8 continuation requests carry only the target number (InDataExchange) or nothing (InCommunicateThru); re-sending the original data forwarded the APDU/command to the card a second time. The mock now captures per-round request parameters, and the MI regression tests assert the continuation shape.
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
