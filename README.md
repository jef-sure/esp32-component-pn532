# PN532 Public API

Copyright (c) 2026 Anton Petrusevich.

This component exports three public headers:

- include/pn532.h: transport creation, device lifetime, ISO14443A polling/select, and ISO-DEP helpers
- include/pn532-mifare.h: low-level MIFARE Classic / Ultralight read-write primitives
- include/pn532-ndef.h: NDEF parsing and one-shot card read helpers

The public API is intentionally split into a small transport/device layer and two optional higher-level layers. Most applications only need pn532.h and pn532-ndef.h.

## Ownership and lifetime

- `pn532_spi_init()`, `pn532_i2c_init()`, and `pn532_uart_init()` return heap-allocated `pn532_bus_t *` handles.
- `pn532_init()` returns a heap-allocated `pn532_t *` device context.
- `pn532_deinit(pn532, true)` frees both the device and its bus.
- `pn532_deinit(pn532, false)` frees only the device; destroy the bus separately with `pn532_bus_destroy()`.
- `pn532_14443_get_all_uids()` returns a heap-allocated `pn532_uids_array_t *`. Release it with `free()`.
- `pn532_ndef_read_card_auto()` returns a heap-allocated `ndef_message_parsed_t *`. Release it with `ndef_free_parsed_message()`.

`pn532_t` is a public struct because the driver is split across multiple source files, but application code should treat it as an owned handle and not modify its fields directly.

## Minimal setup

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

/* ... use the device ... */

pn532_deinit(pn532, true);
```

## Poll, select, and inspect cards

```c
#include <stdlib.h>

#include "pn532.h"

pn532_uids_array_t *uids = pn532_14443_get_all_uids(pn532);
if (uids == NULL) {
    return;
}

for (uint8_t i = 0; i < uids->uids_count; i++) {
    pn532_uid_t *uid = &uids->uids[i];
    uint16_t blocks = 0;
    uint16_t block_size = 0;
    bool needs_reselect = false;

    pn532_14443_detect_selected_card_type_and_capacity(pn532, uid, &blocks, &block_size, &needs_reselect);
    if (needs_reselect) {
        pn532_14443_select_by_uid(pn532, uid);
    }
}

free(uids);
```

Notes:

- `pn532_14443_get_all_uids()` also opens the first discovered target as the active PN532 session.
- `pn532_14443_select_by_uid()` is the right way to reacquire a card after an auth or read failure.
- `pn532_14443_detect_card_type_and_capacity()` is a pure metadata helper; it does not require an active session.

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
                /* text points into msg->raw_data */
            }
        }
    }
    ndef_free_parsed_message(msg);
}
```

Behavior by card family:

- Type 2 / NTAG: the helper re-reads the capability container and retries after a fresh reselect if the first read fails.
- MIFARE Classic 1K: the helper uses MAD1 to identify the contiguous NDEF sector range and returns `NDEF_ERR_NO_NDEF` quickly when the card is not NDEF-mapped.
- DESFire / ISO-DEP: the helper selects the NFC Forum Type 4 application and reads NLEN plus the NDEF file contents.

## Low-level MIFARE access

Include include/pn532-mifare.h only when you need raw block or value operations.

- Prefer `pn532_14443_authenticate()` over `pn532_mifare_authenticate()` unless you already have the exact 4-byte UID fragment required by the MIFARE auth primitive.
- `pn532_mifare_block_read()` reads one 16-byte Classic block, or 16 bytes spanning four Type 2 pages.
- Value helpers are for MIFARE Classic value blocks only.

## API map

- Transport/device lifecycle: `pn532_spi_init()`, `pn532_i2c_init()`, `pn532_uart_init()`, `pn532_init()`, `pn532_deinit()`
- RF field control: `pn532_set_rf_field()`, `pn532_set_rf_on()`, `pn532_set_rf_off()`
- Poll/select/auth: `pn532_14443_get_all_uids()`, `pn532_14443_select_by_uid()`, `pn532_14443_authenticate()`
- Card metadata: `pn532_14443_detect_card_type_and_capacity()`, `pn532_14443_detect_selected_card_type_and_capacity()`
- ISO-DEP / Type 4: `pn532_14443_4_transceive()`, `pn532_14443_4_select_file()`, `pn532_14443_4_read_binary()`
- MIFARE raw access: `pn532_mifare_block_read()`, `pn532_mifare_block_write()`, value operations
- NDEF: `pn532_ndef_read_card_auto()`, `ndef_extract_text()`, `ndef_extract_uri()`, `ndef_result_to_string()`