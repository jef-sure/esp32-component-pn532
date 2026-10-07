# PN532 ESP-IDF Component

[![ESP Component Registry](https://components.espressif.com/components/jef-sure/pn532/badge.svg)](https://components.espressif.com/components/jef-sure/pn532/)

ESP-IDF driver for the NXP PN532 NFC reader over SPI, I2C, or UART (HSU): read card UIDs, read and write NDEF (NTAG / Ultralight, MIFARE Classic, Type 4), and exchange APDUs with ISO14443A cards in reader mode.

- [Quick Start](#quick-start)
- [Choosing A Transport](#choosing-a-transport)
- [Common Tasks](#common-tasks)
- [Multiple Readers And Shared Buses](#multiple-readers-and-shared-buses)
- [Troubleshooting](#troubleshooting)
- [Reliability And Recovery](#reliability-and-recovery)
- [Reference](#reference)

## Quick Start

### 1. Add the component

From the ESP Component Registry:

```sh
idf.py add-dependency "jef-sure/pn532^0.7.1"
```

Or copy this repository to `components/pn532` in your project and add `REQUIRES pn532` to the component that uses it. ESP-IDF 5.2 or newer is required.

### 2. Wire the module

PN532 boards select the host interface with two switches or jumpers, I0 and I1 (NXP AN10609):

| Interface | I0 | I1 |
|-----------|----|----|
| UART (HSU) | 0 | 0 |
| I2C        | 1 | 0 |
| SPI        | 0 | 1 |

Change them only with the module powered off. For the SPI example below connect SCK → GPIO 18, MISO → GPIO 19, MOSI → GPIO 23, SS/NSS → GPIO 5, plus power and GND (ESP32 GPIOs are 3.3 V logic; check your board's supply range). IRQ and RST are optional.

### 3. Read cards

A complete `app_main()` that prints the UID of every card it sees and any URI stored on it:

```c
#include <stdlib.h>

#include "esp_log.h"
#include "pn532.h"
#include "pn532-ndef.h"

static const char *TAG = "nfc";

void app_main(void)
{
    /* SCK, MISO, MOSI, NSS; clock 0 selects the 1 MHz default. */
    pn532_bus_t *bus = pn532_spi_init(SPI2_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_5, 0);
    pn532_t     *nfc = bus ? pn532_init(bus, GPIO_NUM_NC, GPIO_NUM_NC) : NULL;
    if (nfc == NULL) {
        ESP_LOGE(TAG, "PN532 not found: check wiring and the I0/I1 switches");
        pn532_bus_destroy(bus);
        return;
    }

    for (;;) {
        pn532_poll_status_t status;
        pn532_uids_array_t *cards = pn532_14443_get_all_uids_ex(nfc, &status);

        if (status == PN532_POLL_FOUND) {
            for (uint8_t c = 0; c < cards->uids_count; c++) {
                pn532_uid_t *card = &cards->uids[c];
                ESP_LOG_BUFFER_HEX(TAG, card->uid, card->uid_length);

                pn532_ndef_message_parsed_t *msg = NULL;
                if (pn532_ndef_read_card_auto(nfc, card, &msg) == PN532_NDEF_OK) {
                    for (size_t i = 0; i < msg->record_count; i++) {
                        char uri[128];
                        if (pn532_ndef_record_is_uri(&msg->records[i]) &&
                            pn532_ndef_extract_uri(&msg->records[i], uri, sizeof(uri)) > 0) {
                            ESP_LOGI(TAG, "URI: %s", uri);
                        }
                    }
                    pn532_ndef_free_parsed_message(msg);
                }
                pn532_release_target(nfc);
            }
        } else if (status == PN532_POLL_TRANSPORT_ERROR) {
            pn532_recover(nfc); /* the reader stopped answering */
        }

        free(cards);              /* NULL unless a card was found */
        pn532_set_rf_off(nfc);    /* ends the cycle, lets the card reset */
        pn532_delay_ms(250);
    }
}
```

The loop follows the lifecycle every application uses: **poll → read (optional) → release → RF off**. For UID-only access skip the read and the release. `pn532_ndef_read_card_auto()` selects the card itself and handles NTAG/Ultralight, MIFARE Classic (MAD, default keys), and Type 4 layouts.

All headers: `pn532.h` (transports, device, polling, ISO-DEP), `pn532-ndef.h` (NDEF read/write/parse), `pn532-mifare.h` (raw MIFARE primitives, rarely needed).

## Choosing A Transport

| | SPI | I2C | UART (HSU) |
|---|---|---|---|
| Wires (plus power) | 4 | 2 | 2 |
| Readiness | status register, deterministic | status byte | frame header (or IRQ pin) |
| Speed / latency | best | good | good |
| Shares the bus | several PN532 on one host | with any I2C device | no |
| Pick it when | default choice | pins are scarce | SPI hosts are taken |

```c
/* SPI: host, SCK, MISO, MOSI, NSS, clock (<= 0 selects PN532_SPI_DEFAULT_CLOCK_HZ = 1 MHz) */
pn532_bus_t *bus = pn532_spi_init(SPI2_HOST, GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_5, 1000000);

/* I2C: port, SCL, SDA, address (0 selects PN532_I2C_DEFAULT_ADDRESS = 0x24), clock */
pn532_bus_t *bus = pn532_i2c_init(I2C_NUM_0, GPIO_NUM_22, GPIO_NUM_21, 0, 400000);

/* UART: port, TX, RX, baud (<= 0 selects PN532_UART_DEFAULT_BAUD_RATE = 115200) */
pn532_bus_t *bus = pn532_uart_init(UART_NUM_1, GPIO_NUM_17, GPIO_NUM_16, 115200);
```

Every transport is then used the same way: `pn532_init(bus, irq, rst)`, and finally `pn532_deinit(pn532, true)` to free both the device and the bus.

- **IRQ pin (optional).** Pass the GPIO wired to the PN532 IRQ line to `pn532_init()`. The driver then waits on the interrupt instead of polling the bus, and readiness comes from the chip's own signal — most useful on UART. Pass `GPIO_NUM_NC` otherwise.
- **RST pin (optional).** When passed, `pn532_reset()` and `pn532_recover()` pulse it for a hardware reset; without it the reset is logical only.
- **SPI clock.** The PN532 accepts up to 5 MHz, but long wires and cheap modules often are not reliable above 1–2 MHz.
- **UART baud rate.** If the module does not answer at the configured rate, `pn532_init()` probes all nine HSU rates (9600 to 1288000, UM0701-02 §7.2.8) and logs a warning with the rate it found. To run faster, switch both sides at once; the setting is volatile and the module returns to its power-on rate after a power cycle, which `pn532_recover()` detects and follows:

  ```c
  if (!pn532_uart_set_baud_rate(pn532, 921600)) {
      /* Still on the previous rate; pn532_recover() re-synchronises if unsure. */
  }
  ```

Buses created by your application can be shared; see [Multiple Readers And Shared Buses](#multiple-readers-and-shared-buses).

## Sample App

[`examples/simple`](examples/simple/README.md) is a complete SPI project: it logs the firmware version, polls every 250 ms, supports two cards per scan, reads NDEF first and falls back to raw block dumps by card family, and calls `pn532_recover()` after repeated transport failures. Its README covers wiring and building.

## Common Tasks

### Read NDEF

`pn532_ndef_read_card_auto()` takes a UID from the current poll, selects the card, picks the right layout, and returns a heap-allocated parsed message:

```c
#include "pn532-ndef.h"

pn532_ndef_message_parsed_t *msg = NULL;
pn532_ndef_result_t res = pn532_ndef_read_card_auto(pn532, &uids->uids[0], &msg);
if (res == PN532_NDEF_OK) {
    for (size_t i = 0; i < msg->record_count; i++) {
        const pn532_ndef_record_t *rec = &msg->records[i];
        if (pn532_ndef_record_is_text(rec)) {
            const uint8_t *text = NULL;
            size_t text_len = 0;
            char lang[8] = {0};
            bool utf16 = false;
            if (pn532_ndef_extract_text(rec, &text, &text_len, lang, &utf16)) {
                /* text remains valid until msg is freed */
            }
        }
    }
    pn532_ndef_free_parsed_message(msg);
} else {
    ESP_LOGW(TAG, "NDEF: %s", pn532_ndef_result_to_string(res));
}
```

Behavior by card family:

- Type 2 and NTAG: the helper reads the capability container to refine subtype and capacity, then retries after a fresh reselect if needed. A tag without the capability container magic (`E1`) or with an empty data area returns `PN532_NDEF_ERR_NO_NDEF` after that one read; the scan never leaves the data area the container describes.
- MIFARE Classic Mini, 1K, and 4K: the helper authenticates sector 0 with the standard MAD key A `A0 A1 A2 A3 A4 A5` (falling back to the factory default key `FF FF FF FF FF FF`), reads MAD1, and uses the application directory to locate the contiguous range of NDEF-tagged sectors. On 4K cards whose MAD1 GPB advertises version 2, MAD2 is also read and its 23 entries (sectors 17..39) are appended. NDEF sectors must be contiguous; gaps cause `PN532_NDEF_ERR_NO_NDEF`, and so does a directory whose CRC does not match its content. Sector trailers are skipped during reads, and re-authentication is performed at every sector boundary, automatically retrying with the secondary key.
- Type 4 and DESFire-like cards: the helper selects the NFC Forum Type 4 application (AID `D2 76 00 00 85 01 01`), reads the capability container, then reads NLEN plus the NDEF file contents in chunks of MLe − 2 bytes (at most 248). A read-protected NDEF file returns `PN532_NDEF_ERR_ACCESS_DENIED`, a mapping version other than 1.x to 3.x or an extended NDEF file (above 32 KB) `PN532_NDEF_ERR_UNSUPPORTED`, and an NLEN that does not fit the file `PN532_NDEF_ERR_PARSE_FAILED`.

The parser reassembles NDEF chunked records (`CF`) into one logical record with a contiguous payload. It validates the `MB`, `ME`, `CF`, and `TNF_UNCHANGED` sequence and rejects malformed messages. Raw NDEF bytes can be parsed directly with `pn532_ndef_parse_message()`; the returned record storage remains valid until `pn532_ndef_free_parsed_message()`.

### Write a URI to an NTAG

```c
pn532_poll_status_t status;
pn532_uids_array_t *uids = pn532_14443_get_all_uids_ex(pn532, &status);
if (status == PN532_POLL_FOUND && pn532_14443_select_by_uid(pn532, &uids->uids[0])) {
    uint8_t         payload[64];
    pn532_ndef_record_t   records[1];
    pn532_ndef_message_t  message;

    pn532_ndef_message_init(&message, records, 1);
    /* abbreviate=true maps the https://www. prefix to URI identifier 0x02. */
    if (pn532_ndef_make_uri_record(&records[0], "https://www.example.com", true,
                             payload, sizeof(payload))) {
        pn532_ndef_message_add(&message, &records[0]);
        /* NTAG213: 4-byte pages, data starts at page 4, 36 writable pages left. */
        pn532_ndef_result_t res = pn532_ndef_write_to_selected_card(pn532, &message, 4, 4, 36);
        if (res == PN532_NDEF_OK) {
            /* card now carries the URI record */
        }
    }
    pn532_release_target(pn532);
}
free(uids);
pn532_set_rf_off(pn532);
```

Text, MIME, and external records are built the same way with `pn532_ndef_make_text_record()`, `pn532_ndef_make_mime_record()`, and `pn532_ndef_make_external_record()`; several records can be added to one message.

`pn532_ndef_write_to_selected_card()` writes a TLV-wrapped NDEF message to a Type 2 / NTAG style tag (`block_size = 4`) starting at the block you specify. The first block is staged with a hidden TLV length so a concurrent reader never sees a partially updated message; the real length is committed only after the trailing pages have been programmed. The helper is intentionally limited:

- MIFARE Classic block sizes (`block_size = 16`) return `PN532_NDEF_ERR_UNSUPPORTED`. Writing Classic NDEF correctly requires MAD updates and sector-trailer handling, which are out of scope for the helper.
- It does not format blank tags, write the capability container, or update sector trailers.
- The caller must already have the target selected and authenticated where applicable.

### Poll, select, and inspect cards

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
- `pn532_14443_detect_selected_card_type_and_capacity()` additionally asks a SAK `0x00` card what it is, provided the card is selected (`pn532_14443_select_by_uid()`): GET_VERSION tells Ultralight EV1 and NTAG210/212/213/215/216 apart, and a card without GET_VERSION that answers AUTHENTICATE (`1A`) with a challenge is an Ultralight C. A refused probe resets the card, so when `needs_reselect` comes back `true`, call `pn532_14443_select_by_uid()` before the next exchange. An SAK that is not listed but has the ISO14443-4 bit (`0x20`) set, such as `0x60`, is reported as `PN532_MIFARE_DESFIRE` by both helpers.

### Read MIFARE Classic blocks

A complete read cycle for a Classic card: poll, select, authenticate a sector with key A, read its data blocks, then release and turn the field off.

```c
static const uint8_t key_a[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; /* factory default */

pn532_poll_status_t status;
pn532_uids_array_t *uids = pn532_14443_get_all_uids_ex(pn532, &status);
if (status == PN532_POLL_FOUND) {
    pn532_uid_t *uid = &uids->uids[0];

    if (pn532_14443_select_by_uid(pn532, uid)) {
        /* Authenticate sector 1 (blocks 4..7); auth any block of the sector. */
        if (pn532_14443_authenticate(pn532, key_a, 0x60, uid, 4)) {
            uint8_t block[16];
            for (int b = 4; b <= 6; b++) { /* skip the sector trailer (7) */
                if (pn532_14443_block_read(pn532, b, block, sizeof(block))) {
                    /* block holds 16 data bytes */
                } else {
                    break; /* lost the card or auth: reacquire via select */
                }
            }
        }
        pn532_release_target(pn532);
    }
    free(uids);
}
pn532_set_rf_off(pn532);
```

Notes:

- `0x60` selects key A (`0x61` for key B).
- After a failed auth or read, the card must be re-selected before retrying; `pn532_14443_select_by_uid()` handles the re-acquisition.
- For NDEF content prefer `pn532_ndef_read_card_auto()` (see below) — it resolves MAD sectors and keys automatically.

### Exchange APDUs with a Type 4 card

The command and response parsers are optional utilities; the exchange still goes directly through `pn532_14443_4_transceive()`.

```c
static const uint8_t select_ndef[] = {
    0x00, 0xA4, 0x04, 0x00, 0x07,
    0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01,
};

pn532_poll_status_t poll_status;
pn532_uids_array_t *uids = pn532_14443_get_all_uids_ex(pn532, &poll_status);
if (poll_status == PN532_POLL_FOUND && uids->uids_count > 0) {
    pn532_apdu_command_t command;
    if (pn532_apdu_parse_command(select_ndef, sizeof(select_ndef), &command) == ESP_OK &&
        pn532_14443_select_by_uid(pn532, &uids->uids[0])) {
        uint8_t response_buffer[128];
        size_t response_len = sizeof(response_buffer);

        if (pn532_14443_4_transceive(pn532, select_ndef, sizeof(select_ndef),
                                     response_buffer, &response_len)) {
            pn532_apdu_response_t response;
            if (pn532_apdu_parse_response(response_buffer, response_len, &response) == ESP_OK &&
                pn532_apdu_get_status(&response) == PN532_APDU_SW_SUCCESS) {
                /* response.data points into response_buffer; no allocation is made. */
            }
        }
        pn532_release_target(pn532);
    }
}
free(uids);
pn532_set_rf_off(pn532);
```

The command parser can also be used without a PN532 device:

```c
static const uint8_t command_bytes[] = {
    0x00, 0xD0, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x10,
};
pn532_apdu_command_t command;

if (pn532_apdu_parse_command(command_bytes, sizeof(command_bytes), &command) == ESP_OK) {
    /* Case 4S: command.data points at {0x01, 0x02, 0x03}; Le is 16. */
}
```

## Multiple Readers And Shared Buses

### Two PN532 on one SPI bus

Call `pn532_spi_init()` once per PN532 with the same host and bus pins but a different NSS pin. The first call initialises the host bus; the driver frees it when the last PN532 on that host is destroyed. Each returned transport owns a separate `spi_device_handle_t` and controls its own NSS. A second call on an already initialized host is expected and does not log an error.

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

### Sharing a bus with other devices

`pn532_i2c_init()` and `pn532_spi_init()` create the bus themselves. When other devices live on the same port, create the bus in your application and attach the PN532 to it. Destroying the PN532 then removes only its device; the bus and its neighbours stay alive.

```c
i2c_master_bus_config_t cfg = {
    .i2c_port = I2C_NUM_0, .sda_io_num = GPIO_NUM_21, .scl_io_num = GPIO_NUM_22,
    .clk_source = I2C_CLK_SRC_DEFAULT, .glitch_ignore_cnt = 7, .flags.enable_internal_pullup = 1,
};
i2c_master_bus_handle_t i2c_bus;
ESP_ERROR_CHECK(i2c_new_master_bus(&cfg, &i2c_bus));
/* ... add other devices to i2c_bus ... */

pn532_bus_t *bus = pn532_i2c_attach(I2C_NUM_0, 0, 400000); /* ESP-IDF >= 5.4 */
pn532_t *pn532 = pn532_init(bus, GPIO_NUM_NC, GPIO_NUM_NC);
```

For SPI, initialise the host with `spi_bus_initialize()` and call `pn532_spi_attach(host, nss, clock_hz)`.

## Troubleshooting

- **`pn532_init()` returns NULL** — the chip never answered `GetFirmwareVersion`. Check the I0/I1 switches against the transport you initialise, power, ground, and the pin numbers. On SPI try a lower clock; on I2C check pull-ups.
- **`module answers at N baud, not the configured M baud`** — the UART module runs at another rate (often after an earlier `pn532_uart_set_baud_rate()`); the driver found it and continues. Configure that rate to skip the probe on the next boot.
- **`pn532_i2c_attach: requires ESP-IDF >= 5.4`** — attaching to an existing I2C bus needs `i2c_master_get_bus_handle()`; use `pn532_i2c_init()` on older ESP-IDF.
- **`invalid frame header` / `corrupted response ..., requesting retransmission`** — noise or a desynchronised stream. Occasional retransmissions are handled automatically; if they persist, shorten the wires, lower the clock or baud rate, or call `pn532_recover()`.
- **`no ACK for command ... within N ms`** — the transport is not responding at all: check wiring, NSS/address/baud rate, and power. Degrades to `PN532_POLL_TRANSPORT_ERROR` at the polling layer. Repeated occurrences → `pn532_recover()`.
- **Alternating `PN532_POLL_FOUND` / `PN532_POLL_NO_TARGET` with a static card** — the card sits in HALT and does not power down before the next poll. Increase the RF settle delay (`pn532_set_rf_settle_delay()`); the 20 ms default fits a 250 ms two-reader cycle.
- **Frequent `PN532_POLL_TIMEOUT` with a present card** — the response phase is too short for the card. Raise `pn532->timeout_ms` (default 500 ms). For Type 4 APDU exchanges the driver already applies a 1500 ms floor.
- **`PN532_NDEF_ERR_NO_NDEF` on a MIFARE Classic card** — the card has no NFC Forum MAD, the MAD has a wrong CRC, the card uses non-default keys, or its NDEF sectors are not contiguous. Read raw blocks with your own keys instead.
- **Two readers on one SPI bus interfere** — poll sequentially and finish each cycle with `pn532_set_rf_off()`; the settle delay is applied by the driver itself. Never poll both readers concurrently from different tasks.
- **`pn532_in_select: status 0x27`** — the PN532 rejects the command in its current context, typically because the target number is no longer known (for example after an unexpected chip reset). Select fails so the caller re-polls. Deselect/release close the local session successfully on `0x27`; the log line `target already lost (0x27)` at debug level is informational.

## Reliability And Recovery

### Timeouts

Every `pn532_execute_command()` runs in two phases with separate budgets:

- **ACK phase** — the PN532 must acknowledge the command within `pn532->ack_timeout_ms` (default `PN532_ACK_TIMEOUT_MS` = 50 ms; the NXP TAMA reference uses 10 ms). A miss here means the transport or the chip is wedged, so the command fails fast through `PN532_COMMAND_STATUS_ACK_TIMEOUT` instead of burning the full response timeout. At the polling layer this surfaces as `PN532_POLL_TRANSPORT_ERROR`.
- **Response phase** — the full caller timeout (`pn532->timeout_ms`, default 500 ms) applies while the command runs. A miss here is an RF/card-side problem (quiet card, field collision) and maps to `PN532_POLL_TIMEOUT`.

Tune both budgets with `pn532_set_ack_timeout()` and by writing `pn532->timeout_ms`:

```c
pn532_set_ack_timeout(pn532, 30); /* faster dead-transport detection */
pn532->timeout_ms = 800;          /* more headroom for slow cards */
```

After a timeout the driver sends the UM0701-02 ACK-abort frame and drains the full PN532 buffer (an aborted two-card `InListPassiveTarget` can leave ~65 bytes behind; a short drain would corrupt the next frame with `invalid frame header`).

### Unreliable links

Long wires, noisy power, or a module that power-cycles on its own are handled in escalating steps:

1. **Frame** — a response damaged on the line (bad checksum, broken header/postamble, truncated HSU frame) is requested again with the UM0701-02 NACK frame, up to two times. The command is not re-executed, so writes and RF exchanges are never applied twice. Logged as `corrupted response ..., requesting retransmission`.
2. **Command** — a missing ACK or response triggers the ACK-abort and buffer drain described above; the call fails with a typed status.
3. **Device** — `pn532_recover()` resets the chip, checks that it answers, lets the transport re-negotiate the link if it does not (HSU probes all rates), and re-applies the runtime configuration.
4. **Application** — if `pn532_recover()` fails, destroy and re-create the transport, or power-cycle the module.

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

It aborts any in-flight command, resets target/session state, verifies that the chip answers (re-negotiating the link through the transport if it does not), re-applies the SAM/retry configuration, and leaves the RF field off.

### Bus wake-up

The PN532 enters low-power after power-up and after PowerDown. Each transport implements the NXP `phTalTama_WakeUp` role in its own way: SPI wakes on the NSS falling edge, HSU on a `0x55 0x55` preamble, I2C on its own address being recognised (an address-only probe plus an oscillator start-up delay). `pn532_reset()` and `pn532_recover()` send the wake automatically — there is no per-command wake frame, so the SPI/HSU hot paths stay lean.

### RF settle delay

`pn532_set_rf_off()` waits `pn532->rf_settle_delay_ms` (default `PN532_RF_SETTLE_DELAY_MS` = 20 ms) before returning, so a card sitting in HALT powers down and the next `InListPassiveTarget` re-activates it cleanly. With a static card and a 250 ms two-reader poll cycle this keeps every iteration at `PN532_POLL_FOUND` without alternating `FOUND`/`NO_TARGET`. Applications no longer need their own post-RF-off delay; tune or disable it with `pn532_set_rf_settle_delay()` (pass 0 to disable).

## Reference

### Features and scope

- SPI, I2C, and UART/HSU transports; shared SPI/I2C buses via `pn532_spi_attach()` / `pn532_i2c_attach()`
- Optional IRQ-driven readiness; optional hardware reset pin
- ISO14443A polling with up to two cards per scan, typed poll status, selection by UID
- MIFARE Classic authentication and block access; Ultralight / NTAG page access; value-block operations
- ISO-DEP (Type 4) APDU exchange with MI chaining and NAD handling aligned with the NXP TAMA reference (`phTalTama_Transceive`)
- Stateless ISO 7816-4 short APDU parser and response builder
- NDEF reading from Type 2 (Ultralight, NTAG), MIFARE Classic Mini/1K/4K (MAD1/MAD2), and Type 4 cards; chunked-record reassembly
- NDEF record builders (Text, URI, MIME, External), message encoding, and atomic TLV writing to selected Type 2 / NTAG tags
- `GetGeneralStatus` diagnostics, raw `InCommunicateThru`, raw PN532 commands, retry tuning
- Link recovery: NACK retransmission, HSU auto-baud, `pn532_recover()` with transport resync

Not implemented: peer-to-peer, card emulation, formatting blank tags, and writing NDEF to MIFARE Classic.

Requirements: ESP-IDF 5.2 or newer (`pn532_i2c_attach()` needs 5.4). The component's CMakeLists selects `driver` or the split `esp_driver_*` components depending on the ESP-IDF version. Release notes are in [CHANGES.md](CHANGES.md).

### Card session lifecycle

1. Poll for a target and call `pn532_14443_select_by_uid()` to select it. A successful `InSelect` starts the session.
2. Call `pn532_14443_4_transceive()` (or block/NDEF helpers) repeatedly while the target remains selected. If the target is still listed but the session was deselected, ISO-DEP exchange automatically issues `InSelect` for that target number first.
3. End the session with `pn532_deselect_target()`, `pn532_release_target()`, or `pn532_set_rf_off()`. On success (`0x00`) deselect keeps the target listed for reactivation without a field restart; release and RF off invalidate it. Deselect and release verify the returned status byte: `0x27` means the chip already lost the target and is treated as a successful close that clears both the session and the listed-target state — mirroring the NXP TAMA reference — so poll loops cannot wedge. Any other non-zero status fails, leaving the local state untouched. `pn532_in_select()` treats `0x27` as a hard error so callers re-poll.
4. After target loss, RF timeout, or `pn532_recover()`, reacquire the card through polling and `pn532_14443_select_by_uid()` before continuing. A transceive with no listed target fails without starting a new discovery.

### Cards with both MIFARE Classic and ISO-DEP

Some cards (SmartMX, JCOP, and similar) emulate MIFARE Classic on top of an ISO14443-4 chip and report SAK `0x28` (1K) or `0x38` (4K). One activation can serve only one of the two sides: once the PN532 has sent RATS, the card speaks ISO-DEP and refuses MIFARE commands until the field is recycled.

The poll reports such a card with a Classic subtype, and the driver follows the NXP reference stack in treating it as Classic by default: `pn532_14443_select_by_uid()` re-lists it with the PN532's automatic RATS switched off, so authentication, block access, and `pn532_ndef_read_card_auto()` work as on a native Classic card. The next poll switches automatic RATS back on; nothing has to be restored by hand.

To use the ISO-DEP side instead, change the subtype in your copy of the `pn532_uid_t` before selecting. The subtype is the only thing that steers the choice:

```c
pn532_uid_t card = uids->uids[0];
if ((card.sak & 0x20) != 0) {              /* ISO14443-4 capable */
    card.subtype = PN532_MIFARE_DESFIRE;   /* treat as ISO-DEP / Type 4 */
}
if (pn532_14443_select_by_uid(pn532, &card)) {
    /* pn532_14443_4_transceive(), pn532_14443_4_select_file(), ... */
}
```

With that subtype `pn532_ndef_read_card_auto()` also takes the Type 4 path. To switch sides on a card that is already selected, call `pn532_14443_select_by_uid()` again with the other subtype: the driver recycles the field and re-lists the card in the other mode. Both sides cannot be open at the same time.

### APDU utilities

`pn532_14443_4_transceive()` is the APDU exchange API. The APDU utilities are independent of it and of any hardware:

- `pn532_apdu_parse_command()` supports short APDU cases 1, 2S, 3S, and 4S; extended-length APDUs are rejected.
- `pn532_apdu_parse_response()` separates response data from SW1/SW2; `pn532_apdu_build_response()` writes `DATA SW1 SW2` into a caller-provided buffer.
- They do not allocate memory; parsed data pointers refer directly to the caller-owned input buffer.

`pn532_14443_4_select_file()` and `pn532_14443_4_read_binary()` build their APDUs and delegate to `pn532_14443_4_transceive()`. In `pn532_14443_4_read_binary()`, encoded `Le = 0` requests the short-APDU maximum of 256 bytes.

### Tests

The tests in [`test_apps/polling`](test_apps/polling) drive the driver core through a mock bus, with simulated Type 2, MIFARE Classic, and Type 4 cards behind it. They build as an ESP-IDF Unity app for a board, and run on the host without hardware under AddressSanitizer:

```sh
make -C host_test test IDF_PATH=<path to esp-idf>
```

The host run takes the Unity sources from the ESP-IDF checkout and leaves out the bus transports (`src/pn532-bus-*.c`).

### Low-level MIFARE access

Include `include/pn532-mifare.h` only when you need raw block or value operations. For an already selected ISO14443A target, `pn532_14443_block_read()` / `pn532_14443_block_write()` from `pn532.h` are the preferred entry points.

- Prefer `pn532_14443_authenticate()` over `pn532_mifare_authenticate()` unless you already have the exact 4-byte UID fragment required by the on-card auth primitive.
- `pn532_mifare_block_read()` reads one 16-byte MIFARE Classic block, or 16 bytes spanning four Type 2 pages.
- Value-block helpers (`pn532_mifare_increment()`, `pn532_mifare_decrement()`, `pn532_mifare_restore()`, `pn532_mifare_transfer()`) stage the operation in the PN532 transfer buffer; `pn532_mifare_transfer()` commits it. `PN532_MIFARE_CMD_RESTORE` is preferred; `PN532_MIFARE_CMD_STORE` remains as a backward-compatible alias.

### Advanced driver control

`pn532.h` also exposes lower-level control helpers:

- `pn532_set_max_retries()` updates RFConfiguration item `0x05` for ATR, PSL, and passive activation retries.
- `pn532_set_passive_activation_retries()` changes only the passive activation retry count while leaving ATR and PSL retries at their defaults.
- `pn532_execute_command()` sends a raw PN532 command and returns the response payload without the PN532 frame wrapper, TFI byte, or response-code byte. Use it for commands that are not covered by a dedicated helper.

#### Diagnostics with GetGeneralStatus

`pn532_get_general_status()` is a cheap health probe that does not disturb the RF field or the listed targets. It decodes the raw UM0701-02 response (`Err Field NbTg [Tg BrRx BrTx Type]{NbTg} SAMstatus`) into per-target entries:

```c
pn532_general_status_t status;
if (pn532_get_general_status(pn532, &status)) {
    printf("error=0x%02X field=%d targets=%u\n",
           status.error, status.field_present, status.targets_count);
    for (uint8_t i = 0; i < status.targets_count; i++) {
        printf("  Tg%u: rx=%u tx=%u type=0x%02X\n",
               status.targets[i].tg, status.targets[i].br_rx,
               status.targets[i].br_tx, status.targets[i].type);
    }
}
```

Use it after transport failures to see whether the chip still reports a sane state, or to inspect which logical targets the PN532 still holds listed.

#### Raw exchange with InCommunicateThru

`pn532_in_communicate_thru()` forwards bytes verbatim over the RF interface, without the DEP/MIFARE wrapping of `InDataExchange`. Use it for non-standard cards and vendor-specific commands:

```c
const uint8_t cmd[] = {0x30, 0x04}; /* example: raw READ, page 4 */
uint8_t      rx[64];
size_t       rx_len = sizeof(rx);
if (pn532_in_communicate_thru(pn532, cmd, sizeof(cmd), rx, &rx_len, 500)) {
    /* rx holds the raw target reply */
}
```

The target must be selected first (see `pn532_14443_select_by_uid()`). Responses carrying MI (chaining) are drained and concatenated automatically; a NAD byte in the reply is stripped.

### Ownership and lifetime

- `pn532_spi_init()`, `pn532_i2c_init()`, `pn532_uart_init()`, `pn532_spi_attach()`, and `pn532_i2c_attach()` return heap-allocated `pn532_bus_t *` handles. The `*_attach()` variants never free the underlying bus.
- `pn532_init()` returns a heap-allocated `pn532_t *` device context.
- `pn532_deinit(pn532, true)` frees both the device and its bus.
- `pn532_deinit(pn532, false)` frees only the device; destroy the bus separately with `pn532_bus_destroy()`.
- `pn532_14443_get_all_uids_ex()` writes a typed status and, on discovery, returns a heap-allocated `pn532_uids_array_t *`. Release it with `free()`.
- `pn532_14443_get_all_uids()` preserves the legacy nullable return contract.
- `pn532_ndef_read_card_auto()` returns a heap-allocated `pn532_ndef_message_parsed_t *`. Release it with `pn532_ndef_free_parsed_message()`.
- `pn532_ndef_parse_message()` follows the same ownership contract and copies the encoded input into the parsed message.

`pn532_t` is a public struct because the driver is split across multiple source files, but application code should treat it as an owned handle and not modify its fields directly.

### API map

- Transport and device lifecycle: `pn532_spi_init()`, `pn532_i2c_init()`, `pn532_uart_init()`, `pn532_spi_attach()`, `pn532_i2c_attach()`, `pn532_uart_set_baud_rate()`, `pn532_init()`, `pn532_deinit()`, `pn532_reset()`, `pn532_recover()`
- RF field control: `pn532_set_rf_field()`, `pn532_set_rf_on()`, `pn532_set_rf_off()`, `pn532_set_rf_settle_delay()`
- Retry tuning and raw commands: `pn532_set_max_retries()`, `pn532_set_passive_activation_retries()`, `pn532_set_ack_timeout()`, `pn532_execute_command()`
- Diagnostics: `pn532_get_firmware_version()`, `pn532_get_general_status()`
- Poll, select, and auth: `pn532_14443_get_all_uids_ex()`, `pn532_14443_get_all_uids()`, `pn532_release_target()`, `pn532_deselect_target()`, `pn532_14443_select_by_uid()`, `pn532_14443_authenticate()`
- Raw target exchange: `pn532_in_communicate_thru()`
- Selected-tag block access: `pn532_14443_block_read()`, `pn532_14443_block_write()`
- Card metadata: `pn532_14443_detect_card_type_and_capacity()`, `pn532_14443_detect_selected_card_type_and_capacity()`
- ISO-DEP and Type 4: `pn532_14443_4_transceive()`, `pn532_14443_4_select_file()`, `pn532_14443_4_read_binary()`
- APDU utilities: `pn532_apdu_parse_command()`, `pn532_apdu_parse_response()`, `pn532_apdu_build_response()`, `pn532_apdu_get_status()`
- MIFARE raw access: `pn532_mifare_block_read()`, `pn532_mifare_block_write()`, value operations
- NDEF: `pn532_ndef_read_card_auto()`, `pn532_ndef_parse_message()`, `pn532_ndef_message_init()`, `pn532_ndef_message_add()`, `pn532_ndef_record_init()`, `pn532_ndef_make_text_record()`, `pn532_ndef_make_uri_record()`, `pn532_ndef_make_mime_record()`, `pn532_ndef_make_external_record()`, `pn532_ndef_encode_message()`, `pn532_ndef_write_to_selected_card()`, `pn532_ndef_extract_text()`, `pn532_ndef_extract_uri()`, `pn532_ndef_get_record_type()`, `pn532_ndef_decode_smartposter()`, `pn532_ndef_free_parsed_message()`, `pn532_ndef_result_to_string()`