# PN532 ESP-IDF Component

ESP-IDF component for the PN532 NFC reader over SPI, I2C, or UART/HSU.

The driver is focused on reader mode for ISO14443A cards and is split into three public headers:

- `include/pn532.h`: transport creation, device lifetime, retry tuning, raw command access, ISO14443A polling/select, and ISO-DEP helpers
- `include/pn532-mifare.h`: low-level MIFARE Classic and Ultralight read/write primitives
- `include/pn532-ndef.h`: NDEF parsing, encoding, and card read/write helpers

Most applications only need `pn532.h` plus `pn532-ndef.h`.

## Features

- SPI, I2C, and UART/HSU transport backends
- Optional IRQ-driven ready notifications when `pn532_init()` receives a wired IRQ GPIO
- ISO14443A polling with support for up to two cards per scan
- Card selection and MIFARE Classic authentication helpers
- Raw block access for MIFARE Classic, Ultralight, and NTAG tags
- 14443 block read/write compatibility helpers in `pn532.h`
- ISO-DEP helpers for Type 4 style APDU exchange
- Retry tuning helpers for ATR, PSL, and passive activation
- Raw PN532 command access for commands that do not have a dedicated helper yet
- NDEF reading from Type 2 tags such as Ultralight and NTAG
- NDEF reading from MIFARE Classic Mini, 1K, and 4K with MAD1-based NDEF sector discovery (and MAD2 on 4K cards that advertise it)
- NDEF reading from Type 4 cards exposed through the PN532 ISO-DEP path
- NDEF record builders (Text, URI, MIME, External), message encoding, and atomic TLV writing to already selected Type 2 / NTAG style tags

Current scope is reader mode plus low-level NDEF encode/write helpers for already selected tags. Peer-to-peer, card emulation, and full card-formatting or one-shot write flows are not implemented here.

## Requirements

- ESP-IDF `>=5.2.0`
- A PN532 breakout wired for one of the supported host transports

The component uses the split ESP-IDF driver packages (`esp_driver_gpio`, `esp_driver_i2c`, `esp_driver_spi`, `esp_driver_uart`) and the modern I2C master API.

## Add The Component To A Project

### Local component

Place the repository under your application's `components` directory.

```text
my_app/
|- components/
|  \- pn532/
\- main/
```

The example project in this repository uses `REQUIRES pn532`, so the local component folder should be named `pn532`. If you keep a different folder name, update your consuming component's `REQUIRES` list to match.

### Managed component metadata

This repository also includes an `idf_component.yml` manifest for ESP-IDF Component Manager metadata.
See `CHANGES.md` for release notes.

## Sample App

The maintained SPI demo lives in [`examples/simple`](examples/simple/README.md).

It is now laid out as an ESP-IDF example project, with a project-level `CMakeLists.txt` and a separate `main` component under `examples/simple/main`.

It shows how to:

- initialize the PN532 over SPI
- read and log the PN532 firmware identifier
- poll for ISO14443A cards every 250 ms
- print discovered UIDs
- attempt an NDEF read first
- fall back to raw block dumps by card family

The example README covers wiring, project layout, and how to make the `pn532` component available when building the example directly.

## Minimal Setup

```c
#include <stdlib.h>

#include "pn532.h"

pn532_bus_t *bus = pn532_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_5, 1000000);
if (bus == NULL) {
    return;
}

pn532_t *pn532 = pn532_init(bus, GPIO_NUM_NC, GPIO_NUM_NC);
if (pn532 == NULL) {
    pn532_bus_destroy(bus);
    return;
}

uint32_t firmware = pn532_get_firmware_version(pn532);
if (firmware == 0) {
    pn532_deinit(pn532, true);
    return;
}

/* ... use the device ... */

pn532_deinit(pn532, true);
```

Alternative transport constructors:

- `pn532_i2c_init(port, scl, sda, device_address, clock_speed_hz)`
- `pn532_uart_init(uart_num, tx, rx, baud_rate)`

For I2C, pass `0` as the address to use `PN532_I2C_DEFAULT_ADDRESS`. For UART, pass a non-positive baud rate to use `PN532_UART_DEFAULT_BAUD_RATE`.

`pn532_init(bus, irq, rst)` also accepts an optional IRQ GPIO. When the PN532 IRQ line is wired and passed here, the driver can use IRQ-ready notifications while waiting for ACK and response frames. Pass `GPIO_NUM_NC` when IRQ is not connected.

## Poll, Select, And Inspect Cards

```c
#include <stdlib.h>

#include "pn532.h"

pn532_poll_status_t status;
pn532_uids_array_t *uids = pn532_14443_get_all_uids_ex(pn532, &status);
if (status == PN532_POLL_NO_TARGET) {
    pn532_set_rf_off(pn532);
    return;
}
if (status != PN532_POLL_FOUND) {
    /* Handle PN532_POLL_TIMEOUT or PN532_POLL_TRANSPORT_ERROR. */
    pn532_set_rf_off(pn532);
    return;
}

for (uint8_t i = 0; i < uids->uids_count; i++) {
    pn532_uid_t *uid = &uids->uids[i];
    uint16_t blocks = 0;
    uint16_t block_size = 0;

    if (!pn532_14443_detect_card_type_and_capacity(uid, &blocks, &block_size)) {
        continue;
    }

    if (!pn532_14443_select_by_uid(pn532, uid)) {
        continue;
    }

    /* Read the selected card here. */
    pn532_release_target(pn532);
}

free(uids);
pn532_set_rf_off(pn532);
```

Notes:

- `pn532_14443_get_all_uids_ex()` distinguishes a successful discovery, no target, command timeout, transport failure, malformed response, invalid arguments, and allocation failure through its status output. Its returned array is owned by the caller only for `PN532_POLL_FOUND`.
- `pn532_14443_get_all_uids()` remains available as a compatibility wrapper, but still returns `NULL` for every non-success status.
- Each returned UID includes its PN532 target number in `uid->tg`. While the current RF field remains active, `pn532_14443_select_by_uid()` uses it for a direct `InSelect` without polling again.
- Polling does not select a target or open a target session. For UID-only polling, finish with `pn532_set_rf_off()`; no release is needed.
- Before reading a discovered card, select it with `pn532_14443_select_by_uid()`. After a selected-card operation, finish with `pn532_release_target()` followed by `pn532_set_rf_off()`.
- `pn532_14443_select_by_uid()` is the right way to reacquire a card after an auth or read failure.
- `pn532_14443_detect_card_type_and_capacity()` is a metadata helper that updates `uid->subtype`, `uid->blocks_count`, and `uid->block_size` in place.
- `pn532_14443_detect_selected_card_type_and_capacity()` currently mirrors the same local detection and always sets `needs_reselect` to `false`.

## Two PN532 Devices On One SPI Bus

Call `pn532_spi_init()` once per PN532 with the same host and bus pins but a different NSS pin. ESP-IDF owns the shared host bus; each returned transport owns a separate `spi_device_handle_t` and controls its own NSS. A second call on an already initialized host is expected and does not log an error.

Poll devices sequentially and turn off one reader before polling the other. The driver inserts the RF settle delay after each RF off itself, so no manual post-off delay is needed:

```c
pn532_bus_t *bus_a = pn532_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_5, 1000000);
pn532_bus_t *bus_b = pn532_spi_init(SPI3_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_17, 1000000);
pn532_t *reader_a = pn532_init(bus_a, GPIO_NUM_NC, GPIO_NUM_NC);
pn532_t *reader_b = pn532_init(bus_b, GPIO_NUM_NC, GPIO_NUM_NC);

for (;;) {
    pn532_poll_status_t status_a;
    pn532_uids_array_t *uids_a = pn532_14443_get_all_uids_ex(reader_a, &status_a);
    /* Consume uids_a when status_a == PN532_POLL_FOUND. */
    free(uids_a);
    pn532_set_rf_off(reader_a); /* includes the RF settle delay */

    pn532_poll_status_t status_b;
    pn532_uids_array_t *uids_b = pn532_14443_get_all_uids_ex(reader_b, &status_b);
    /* Consume uids_b when status_b == PN532_POLL_FOUND. */
    free(uids_b);
    pn532_set_rf_off(reader_b);
}
```

For UID-only discovery the lifecycle is `poll -> RF off`. When card data is read, use `poll -> select/read -> release -> RF off`. Turning RF off successfully invalidates the local target and session state, so a later `pn532_release_target()` is a no-op and does not send stale `InRelease`.

## Timeouts And Recovery

Every `pn532_execute_command()` runs in two phases with separate budgets:

- **ACK phase** — the PN532 must acknowledge the command within `pn532->ack_timeout_ms` (default `PN532_ACK_TIMEOUT_MS` = 50 ms; the NXP TAMA reference uses 10 ms). A miss here means the transport or the chip is wedged, so the command fails fast through `PN532_COMMAND_STATUS_ACK_TIMEOUT` instead of burning the full response timeout. At the polling layer this surfaces as `PN532_POLL_TRANSPORT_ERROR`.
- **Response phase** — the full caller timeout (`pn532->timeout_ms`, default 500 ms) applies while the command runs. A miss here is an RF/card-side problem (quiet card, field collision) and maps to `PN532_POLL_TIMEOUT`.

Tune both budgets with `pn532_set_ack_timeout()` and by writing `pn532->timeout_ms`:

```c
pn532_set_ack_timeout(pn532, 30); /* faster dead-transport detection */
pn532->timeout_ms = 800;          /* more headroom for slow cards */
```

After a timeout the driver sends the UM0701-02 ACK-abort frame and drains the full PN532 buffer (an aborted two-card `InListPassiveTarget` can leave ~65 bytes behind; a short drain would corrupt the next frame with `invalid frame header`).

### pn532_recover()

When a device keeps failing (repeated `PN532_POLL_TRANSPORT_ERROR`, wedged ACK phase), `pn532_recover()` performs a full software re-initialisation on the existing bus — no `pn532_deinit()` / `pn532_spi_init()` / `pn532_init()` cycle needed:

```c
if (status == PN532_POLL_TRANSPORT_ERROR) {
    if (++failures >= 3) {
        if (!pn532_recover(pn532)) {
            /* Transport is gone: deinit and re-create the bus. */
        }
        failures = 0;
    }
}
```

It aborts any in-flight command, resets target/session state, re-applies the SAM/retry configuration, verifies the firmware version, and leaves the RF field off.

### Bus wake-up

The PN532 enters low-power after power-up and after PowerDown. Each transport implements the NXP `phTalTama_WakeUp` role in its own way: SPI wakes on the NSS falling edge, HSU on a `0x55 0x55` preamble, I2C on a START condition (a zero-length probe plus an oscillator start-up delay). `pn532_reset()` and `pn532_recover()` send the wake automatically — there is no per-command wake frame, so the SPI/HSU hot paths stay lean.

### RF settle delay

`pn532_set_rf_off()` waits `pn532->rf_settle_delay_ms` (default `PN532_RF_SETTLE_DELAY_MS` = 20 ms) before returning, so a card sitting in HALT powers down and the next `InListPassiveTarget` re-activates it cleanly. With a static card and a 250 ms two-reader poll cycle this keeps every iteration at `PN532_POLL_FOUND` without alternating `FOUND`/`NO_TARGET`. Applications no longer need their own post-RF-off delay; tune or disable it with `pn532_set_rf_settle_delay()` (pass 0 to disable).

### Soft deselect

`pn532_deselect_target()` issues `InDeselect` (0x44): the card goes to HALT but stays listed inside the PN532, so a later select reactivates it without a field restart. Use `pn532_release_target()` when you are done with the card entirely.

## Read NDEF

```c
#include "pn532-ndef.h"

ndef_message_parsed_t *msg = NULL;
ndef_result_t res = pn532_ndef_read_card_auto(pn532, &uids->uids[0], &msg);
if (res == NDEF_OK) {
    for (size_t i = 0; i < msg->record_count; i++) {
        const ndef_record_t *rec = &msg->records[i];
        if (ndef_record_is_text(rec)) {
            const uint8_t *text = NULL;
            size_t text_len = 0;
            char lang[8] = {0};
            bool utf16 = false;
            if (ndef_extract_text(rec, &text, &text_len, lang, &utf16)) {
                /* text remains valid until msg is freed */
            }
        }
    }
    ndef_free_parsed_message(msg);
}
```

Behavior by card family:

- Type 2 and NTAG: the helper reads the capability container to refine subtype and capacity, then retries after a fresh reselect if needed.
- MIFARE Classic Mini, 1K, and 4K: the helper authenticates sector 0 with the standard MAD key A `A0 A1 A2 A3 A4 A5` (falling back to the factory default key `FF FF FF FF FF FF`), reads MAD1, and uses the application directory to locate the contiguous range of NDEF-tagged sectors. On 4K cards whose MAD1 GPB advertises version 2, MAD2 is also read and its 23 entries (sectors 17..39) are appended. NDEF sectors must be contiguous; gaps cause `NDEF_ERR_NO_NDEF`. Sector trailers are skipped during reads, and re-authentication is performed at every sector boundary, automatically retrying with the secondary key.
- Type 4 and DESFire-like cards: the helper selects the NFC Forum Type 4 application (AID `D2 76 00 00 85 01 01`), reads the capability container, then reads NLEN plus the NDEF file contents in MLe-sized chunks (capped at 250 bytes).

The parser reassembles NDEF chunked records (`CF`) into one logical record with a contiguous payload. It validates the `MB`, `ME`, `CF`, and `TNF_UNCHANGED` sequence and rejects malformed messages. Raw NDEF bytes can be parsed directly with `ndef_parse_message()`; the returned record storage remains valid until `ndef_free_parsed_message()`.

## Build And Write NDEF

`pn532-ndef.h` also exposes record builders, an encoder, and a low-level write helper for tags that are already selected and writable.

```c
#include "pn532-ndef.h"

uint8_t text_payload[64];
ndef_record_t records[1];
ndef_message_t message;

ndef_message_init(&message, records, 1);
if (ndef_make_text_record(&records[0], "en", (const uint8_t *)"hello", 5, false, text_payload, sizeof(text_payload))) {
    ndef_message_add(&message, &records[0]);
    ndef_write_to_selected_card(pn532, &message, 4, 4, 64);
}
```

`ndef_write_to_selected_card()` writes a TLV-wrapped NDEF message to a Type 2 / NTAG style tag (`block_size = 4`) starting at the block you specify. The first block is staged with a hidden TLV length so a concurrent reader never sees a partially updated message; the real length is committed only after the trailing pages have been programmed.

The helper is intentionally limited:

- MIFARE Classic block sizes (`block_size = 16`) return `NDEF_ERR_UNSUPPORTED`. Writing Classic NDEF correctly requires MAD updates and sector-trailer handling, which are out of scope for the helper.
- It does not format blank tags, write the capability container, or update sector trailers.
- The caller must already have the target selected and authenticated where applicable.

## Low-Level MIFARE Access

Include `include/pn532-mifare.h` only when you need raw block or value operations. For an already selected ISO14443A target, `pn532_14443_block_read()` / `pn532_14443_block_write()` from `pn532.h` are the preferred entry points.

- Prefer `pn532_14443_authenticate()` over `pn532_mifare_authenticate()` unless you already have the exact 4-byte UID fragment required by the on-card auth primitive.
- `pn532_mifare_block_read()` reads one 16-byte MIFARE Classic block, or 16 bytes spanning four Type 2 pages.
- Value-block helpers (`pn532_mifare_increment()`, `pn532_mifare_decrement()`, `pn532_mifare_restore()`, `pn532_mifare_transfer()`) stage the operation in the PN532 transfer buffer; `pn532_mifare_transfer()` commits it. `MIFARE_CMD_RESTORE` is preferred; `MIFARE_CMD_STORE` remains as a backward-compatible alias.

## Advanced Driver Control

`pn532.h` also exposes lower-level control helpers:

- `pn532_set_max_retries()` updates RFConfiguration item `0x05` for ATR, PSL, and passive activation retries.
- `pn532_set_passive_activation_retries()` changes only the passive activation retry count while leaving ATR and PSL retries at their defaults.
- `pn532_execute_command()` sends a raw PN532 command and returns the response payload without the PN532 frame wrapper, TFI byte, or response-code byte. Use it for commands that are not covered by a dedicated helper.

## Ownership And Lifetime

- `pn532_spi_init()`, `pn532_i2c_init()`, and `pn532_uart_init()` return heap-allocated `pn532_bus_t *` handles.
- `pn532_init()` returns a heap-allocated `pn532_t *` device context.
- `pn532_deinit(pn532, true)` frees both the device and its bus.
- `pn532_deinit(pn532, false)` frees only the device; destroy the bus separately with `pn532_bus_destroy()`.
- `pn532_14443_get_all_uids_ex()` writes a typed status and, on discovery, returns a heap-allocated `pn532_uids_array_t *`. Release it with `free()`.
- `pn532_14443_get_all_uids()` preserves the legacy nullable return contract.
- `pn532_ndef_read_card_auto()` returns a heap-allocated `ndef_message_parsed_t *`. Release it with `ndef_free_parsed_message()`.
- `ndef_parse_message()` follows the same ownership contract and copies the encoded input into the parsed message.

`pn532_t` is a public struct because the driver is split across multiple source files, but application code should treat it as an owned handle and not modify its fields directly.

## API Map

- Transport and device lifecycle: `pn532_spi_init()`, `pn532_i2c_init()`, `pn532_uart_init()`, `pn532_init()`, `pn532_deinit()`, `pn532_reset()`, `pn532_recover()`
- RF field control: `pn532_set_rf_field()`, `pn532_set_rf_on()`, `pn532_set_rf_off()`, `pn532_set_rf_settle_delay()`
- Retry tuning and raw commands: `pn532_set_max_retries()`, `pn532_set_passive_activation_retries()`, `pn532_set_ack_timeout()`, `pn532_execute_command()`
- Poll, select, and auth: `pn532_14443_get_all_uids_ex()`, `pn532_14443_get_all_uids()`, `pn532_release_target()`, `pn532_deselect_target()`, `pn532_14443_select_by_uid()`, `pn532_14443_authenticate()`
- Selected-tag block access: `pn532_14443_block_read()`, `pn532_14443_block_write()`
- Card metadata: `pn532_14443_detect_card_type_and_capacity()`, `pn532_14443_detect_selected_card_type_and_capacity()`
- ISO-DEP and Type 4: `pn532_14443_4_transceive()`, `pn532_14443_4_select_file()`, `pn532_14443_4_read_binary()`
- MIFARE raw access: `pn532_mifare_block_read()`, `pn532_mifare_block_write()`, value operations
- NDEF: `pn532_ndef_read_card_auto()`, `ndef_parse_message()`, `ndef_message_init()`, `ndef_message_add()`, `ndef_record_init()`, `ndef_make_text_record()`, `ndef_make_uri_record()`, `ndef_make_mime_record()`, `ndef_make_external_record()`, `ndef_encode_message()`, `ndef_write_to_selected_card()`, `ndef_extract_text()`, `ndef_extract_uri()`, `ndef_get_record_type()`, `ndef_decode_smartposter()`, `ndef_free_parsed_message()`, `ndef_result_to_string()`