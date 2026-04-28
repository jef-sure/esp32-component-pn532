#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "pn532.h"
#include "pn532-mifare.h"
#include "pn532-ndef.h"

static const char *TAG = "main";

#define PN532_SPI_HOST_ID  SPI3_HOST
#define PN532_SPI_CLOCK_HZ 1000000

#define PN532_PIN_SCK  GPIO_NUM_18
#define PN532_PIN_MISO GPIO_NUM_19
#define PN532_PIN_MOSI GPIO_NUM_23
#define PN532_PIN_NSS  GPIO_NUM_5
#define PN532_PIN_IRQ  GPIO_NUM_NC
#define PN532_PIN_RST  GPIO_NUM_NC

#define PN532_SAMPLE_MAX_UIDS 2
#define PN532_SAMPLE_POLL_MS  250

#define PN532_SAMPLE_ENABLE_DUMP 1
#define PN532_SAMPLE_ENABLE_NDEF 1

static void pn532_format_uid(const pn532_uid_t *uid, char *buffer, size_t buffer_len)
{
    size_t offset = 0;

    if (uid == NULL || buffer == NULL || buffer_len == 0) {
        return;
    }

    buffer[0] = '\0';
    for (int index = 0; index < uid->uid_length && offset < buffer_len; index++) {
        int written =
            snprintf(buffer + offset, buffer_len - offset, "%s%02X", (index == 0) ? "" : ":", uid->uid[index]);
        if (written < 0) {
            buffer[0] = '\0';
            return;
        }
        if ((size_t)written >= buffer_len - offset) {
            break;
        }
        offset += (size_t)written;
    }
}

static bool pn532_uids_match(const pn532_uids_array_t *uids, const pn532_uid_t *last_uids, int last_count)
{
    int count;

    if (uids == NULL) {
        return last_count == 0;
    }

    count = uids->uids_count;
    if (count > PN532_SAMPLE_MAX_UIDS) {
        count = PN532_SAMPLE_MAX_UIDS;
    }
    if (count != last_count) {
        return false;
    }

    for (int index = 0; index < count; index++) {
        const pn532_uid_t *current  = &uids->uids[index];
        const pn532_uid_t *previous = &last_uids[index];

        if (current->uid_length != previous->uid_length || current->sak != previous->sak ||
            current->atqa != previous->atqa || memcmp(current->uid, previous->uid, (size_t)current->uid_length) != 0) {
            return false;
        }
    }

    return true;
}

static void pn532_copy_uids_snapshot(const pn532_uids_array_t *uids, pn532_uid_t *last_uids, int *last_count)
{
    int count = 0;

    if (last_uids == NULL || last_count == NULL) {
        return;
    }

    memset(last_uids, 0, sizeof(pn532_uid_t) * PN532_SAMPLE_MAX_UIDS);
    if (uids != NULL) {
        count = uids->uids_count;
        if (count > PN532_SAMPLE_MAX_UIDS) {
            count = PN532_SAMPLE_MAX_UIDS;
        }
        for (int index = 0; index < count; index++) {
            last_uids[index] = uids->uids[index];
        }
    }

    *last_count = count;
}

static void pn532_log_detected_cards(const pn532_uids_array_t *uids)
{
    int count;

    if (uids == NULL) {
        return;
    }

    count = uids->uids_count;
    if (count > PN532_SAMPLE_MAX_UIDS) {
        count = PN532_SAMPLE_MAX_UIDS;
    }

    ESP_LOGI(TAG, "Detected %d ISO14443A target(s)", count);
    for (int index = 0; index < count; index++) {
        const pn532_uid_t *uid                              = &uids->uids[index];
        char               uid_string[sizeof(uid->uid) * 3] = {0};

        pn532_format_uid(uid, uid_string, sizeof(uid_string));
        ESP_LOGI(TAG, "Card %d UID=%s ATQA=0x%04X SAK=0x%02X", index + 1, uid_string, (unsigned int)uid->atqa,
                 (unsigned int)uid->sak);
    }
}

static void pn532_log_block(int blockno, const uint8_t *data, size_t len)
{
    char line[3 * 16 + 1];
    size_t offset = 0;

    line[0] = '\0';
    for (size_t i = 0; i < len && offset + 3 < sizeof(line); i++) {
        int n = snprintf(line + offset, sizeof(line) - offset, "%02X ", data[i]);
        if (n < 0) {
            break;
        }
        offset += (size_t)n;
    }
    ESP_LOGI(TAG, "  blk %3d: %s", blockno, line);
}

static void pn532_dump_mifare_classic(pn532_t *pn532, const pn532_uid_t *uid)
{
    static const uint8_t key_factory[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static const uint8_t key_ndef[6]    = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
    static const uint8_t key_mad[6]     = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    static const struct {
        const uint8_t *key;
        const char    *name;
    } key_set[] = {
        {key_factory, "FFFFFFFFFFFF"},
        {key_ndef,    "D3F7D3F7D3F7"},
        {key_mad,     "A0A1A2A3A4A5"},
    };
    uint8_t block[16];

    if (uid->blocks_count == 0 || uid->block_size != 16) {
        return;
    }

    if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, uid)) {
        ESP_LOGW(TAG, "select_by_uid failed; skipping dump");
        return;
    }

    ESP_LOGI(TAG, "Dumping %u blocks (try keys FF.., D3F7.., A0A1..)", (unsigned)uid->blocks_count);
    for (uint16_t blk = 0; blk < uid->blocks_count; blk++) {
        bool     first_in_sector;
        uint16_t sector_size;
        if (blk < 128) {
            sector_size     = 4;
            first_in_sector = (blk % 4) == 0;
        } else {
            sector_size     = 16;
            first_in_sector = ((blk - 128) % 16) == 0;
        }

        if (first_in_sector) {
            bool authed = false;
            if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, uid)) {
                ESP_LOGW(TAG, "  select failed at blk %u; skipping sector", (unsigned)blk);
                blk += sector_size - 1;
                continue;
            }
            for (size_t k = 0; k < sizeof(key_set) / sizeof(key_set[0]); k++) {
                if (pn532_14443_authenticate(pn532, key_set[k].key, MIFARE_CMD_AUTH_A, uid, (int)blk)) {
                    authed = true;
                    if (k != 0) {
                        ESP_LOGI(TAG, "  sector @blk %u authed with key A %s", (unsigned)blk, key_set[k].name);
                    }
                    break;
                }
                if (pn532->inListedTag == 0) {
                    break;
                }
                /* PN532 halts the card on auth failure; re-select before next attempt. */
                if (!pn532_14443_select_by_uid(pn532, uid)) {
                    break;
                }
            }
            if (!authed) {
                ESP_LOGW(TAG, "  auth failed at blk %u; skipping sector", (unsigned)blk);
                blk += sector_size - 1;
                continue;
            }
        }

        if (!pn532_mifare_block_read(pn532, (int)blk, block, sizeof(block))) {
            ESP_LOGW(TAG, "  read failed at blk %u; skipping sector", (unsigned)blk);
            blk = (uint16_t)((blk / sector_size + 1) * sector_size - 1);
            continue;
        }
        pn532_log_block((int)blk, block, sizeof(block));
    }
}

static void pn532_dump_ultralight(pn532_t *pn532, const pn532_uid_t *uid)
{
    uint8_t block[16];

    if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, uid)) {
        ESP_LOGW(TAG, "select_by_uid failed; skipping dump");
        return;
    }

    ESP_LOGI(TAG, "Dumping %u pages", (unsigned)uid->blocks_count);
    /* Ultralight READ returns 16 bytes (4 pages) starting at the requested page. */
    for (uint16_t page = 0; page < uid->blocks_count; page += 4) {
        if (!pn532_mifare_block_read(pn532, (int)page, block, sizeof(block))) {
            ESP_LOGW(TAG, "  read failed at page %u; stopping dump", (unsigned)page);
            return;
        }
        for (int i = 0; i < 4 && (page + i) < uid->blocks_count; i++) {
            pn532_log_block((int)(page + i), &block[i * 4], 4);
        }
    }
}

static void pn532_dump_desfire(pn532_t *pn532, const pn532_uid_t *uid)
{
    static const uint8_t ndef_aid[]   = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    static const uint8_t cc_file_id[] = {0xE1, 0x03};

    if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, uid)) {
        ESP_LOGW(TAG, "select_by_uid failed; skipping dump");
        return;
    }

    ESP_LOGI(TAG, "DESFire / Type 4 — dumping NDEF application");

    if (!pn532_14443_4_select_file(pn532, ndef_aid, sizeof(ndef_aid))) {
        ESP_LOGI(TAG, "  no NDEF application on this card");
        return;
    }
    if (!pn532_14443_4_select_file(pn532, cc_file_id, sizeof(cc_file_id))) {
        ESP_LOGI(TAG, "  CC file not found");
        return;
    }

    uint8_t cc[15];
    size_t  cc_got = sizeof(cc);
    if (!pn532_14443_4_read_binary(pn532, 0, sizeof(cc), cc, &cc_got) || cc_got < 15) {
        ESP_LOGW(TAG, "  CC read failed");
        return;
    }
    pn532_log_block(-1, cc, cc_got); /* CC */
    uint16_t mle           = ((uint16_t)cc[3] << 8) | cc[4];
    uint8_t  ndef_fid_be[2] = {cc[9], cc[10]};
    uint16_t max_ndef_size = ((uint16_t)cc[11] << 8) | cc[12];
    ESP_LOGI(TAG, "  CC: ver=0x%02X MLe=%u MLc=%u NDEF FID=%02X%02X max=%u r/w=%02X/%02X",
             cc[2], mle, ((uint16_t)cc[5] << 8) | cc[6], ndef_fid_be[0], ndef_fid_be[1], max_ndef_size, cc[13], cc[14]);

    if (!pn532_14443_4_select_file(pn532, ndef_fid_be, sizeof(ndef_fid_be))) {
        ESP_LOGW(TAG, "  SELECT NDEF file failed");
        return;
    }

    uint8_t nlen_buf[2];
    size_t  got = sizeof(nlen_buf);
    if (!pn532_14443_4_read_binary(pn532, 0, 2, nlen_buf, &got) || got < 2) {
        ESP_LOGW(TAG, "  NLEN read failed");
        return;
    }
    uint16_t nlen = ((uint16_t)nlen_buf[0] << 8) | nlen_buf[1];
    ESP_LOGI(TAG, "  NLEN=%u", nlen);

    uint16_t chunk_max = (mle == 0 || mle > 250) ? 250u : mle;
    uint16_t off       = 2;
    uint16_t remaining = nlen;
    uint8_t  buf[64];
    while (remaining > 0) {
        uint8_t want = (remaining > chunk_max) ? (uint8_t)chunk_max : (uint8_t)remaining;
        if (want > sizeof(buf)) {
            want = sizeof(buf);
        }
        got = want;
        if (!pn532_14443_4_read_binary(pn532, off, want, buf, &got) || got != want) {
            ESP_LOGW(TAG, "  NDEF read failed @off=%u", off);
            return;
        }
        for (size_t i = 0; i < got; i += 16) {
            size_t line = (got - i > 16) ? 16 : (got - i);
            pn532_log_block((int)(off + i), buf + i, line);
        }
        off       += want;
        remaining -= want;
    }
}

static void pn532_dump_card(pn532_t *pn532, const pn532_uid_t *uid)
{
    switch (uid->subtype) {
    case PN532_MIFARE_CLASSIC_1K:
    case PN532_MIFARE_CLASSIC_4K:
    case PN532_MIFARE_CLASSIC_MINI:
        pn532_dump_mifare_classic(pn532, uid);
        break;
    case PN532_MIFARE_ULTRALIGHT:
    case PN532_MIFARE_ULTRALIGHT_C:
    case PN532_MIFARE_ULTRALIGHT_EV1:
    case PN532_MIFARE_NTAG213:
    case PN532_MIFARE_NTAG215:
    case PN532_MIFARE_NTAG216:
        pn532_dump_ultralight(pn532, uid);
        break;
    case PN532_MIFARE_DESFIRE:
        pn532_dump_desfire(pn532, uid);
        break;
    default:
        ESP_LOGI(TAG, "Block dump not supported for subtype %d", (int)uid->subtype);
        break;
    }
}

static void pn532_log_record(int index, const ndef_record_t *rec)
{
    ndef_record_type_t type = ndef_get_record_type(rec);

    switch (type) {
    case NDEF_RECORD_TYPE_TEXT: {
        const uint8_t *txt    = NULL;
        size_t         tx_len = 0;
        char           lang[8] = {0};
        bool           utf16  = false;
        if (ndef_extract_text(rec, &txt, &tx_len, lang, &utf16)) {
            char preview[128];
            size_t copy = (tx_len < sizeof(preview) - 1) ? tx_len : sizeof(preview) - 1;
            memcpy(preview, txt, copy);
            preview[copy] = '\0';
            ESP_LOGI(TAG, "    rec %d Text [%s,%s]: %s", index, lang, utf16 ? "UTF-16" : "UTF-8", preview);
        } else {
            ESP_LOGI(TAG, "    rec %d Text (parse failed)", index);
        }
        break;
    }
    case NDEF_RECORD_TYPE_URI: {
        char uri[160];
        if (ndef_extract_uri(rec, uri, sizeof(uri)) > 0) {
            ESP_LOGI(TAG, "    rec %d URI: %s", index, uri);
        } else {
            ESP_LOGI(TAG, "    rec %d URI (parse failed)", index);
        }
        break;
    }
    case NDEF_RECORD_TYPE_SMARTPOSTER:
        ESP_LOGI(TAG, "    rec %d SmartPoster (%u bytes)", index, (unsigned)rec->payload_len);
        break;
    case NDEF_RECORD_TYPE_MIME:
        ESP_LOGI(TAG, "    rec %d MIME type_len=%u payload_len=%u", index, (unsigned)rec->type_len,
                 (unsigned)rec->payload_len);
        break;
    case NDEF_RECORD_TYPE_EXTERNAL:
        ESP_LOGI(TAG, "    rec %d External type_len=%u payload_len=%u", index, (unsigned)rec->type_len,
                 (unsigned)rec->payload_len);
        break;
    case NDEF_RECORD_TYPE_EMPTY:
        ESP_LOGI(TAG, "    rec %d Empty", index);
        break;
    default:
        ESP_LOGI(TAG, "    rec %d TNF=0x%02X type_len=%u payload_len=%u", index, (unsigned)rec->tnf,
                 (unsigned)rec->type_len, (unsigned)rec->payload_len);
        break;
    }
}

static ndef_result_t pn532_read_ndef(pn532_t *pn532, pn532_uid_t *uid)
{
    ndef_message_parsed_t *msg = NULL;
    ndef_result_t          res = pn532_ndef_read_card_auto(pn532, uid, &msg);

    if (res != NDEF_OK) {
        ESP_LOGI(TAG, "  NDEF: %s", ndef_result_to_string(res));
        return res;
    }

    ESP_LOGI(TAG, "  NDEF: %u record(s), %u bytes", (unsigned)msg->record_count, (unsigned)msg->raw_data_len);
    for (size_t i = 0; i < msg->record_count; i++) {
        pn532_log_record((int)i, &msg->records[i]);
    }
    ndef_free_parsed_message(msg);
    return NDEF_OK;
}

static void pn532_process_card(pn532_t *pn532, const pn532_uid_t *uid, int index, bool needs_select)
{
    pn532_uid_t working_uid;
    uint16_t    blocks_count   = 0;
    uint16_t    block_size     = 0;
    bool        needs_reselect = false;

    if (pn532 == NULL || uid == NULL) {
        return;
    }

    working_uid = *uid;

    if (needs_select && !pn532_14443_select_by_uid(pn532, &working_uid)) {
        ESP_LOGW(TAG, "select_by_uid failed; skipping card %d", index + 1);
        return;
    }

    if (!pn532_14443_detect_selected_card_type_and_capacity(pn532, &working_uid, &blocks_count, &block_size, &needs_reselect)) {
        ESP_LOGW(TAG, "detect_card_type_and_capacity failed; skipping card %d", index + 1);
        return;
    }

    if (needs_reselect && !pn532_14443_select_by_uid(pn532, &working_uid)) {
        ESP_LOGW(TAG, "select_by_uid failed after detect; skipping card %d", index + 1);
        return;
    }

#if PN532_SAMPLE_ENABLE_NDEF
    ESP_LOGI(TAG, "--- Card %d NDEF ---", index + 1);
    ndef_result_t ndef_res = pn532_read_ndef(pn532, &working_uid);
#else
    ndef_result_t ndef_res = NDEF_ERR_UNSUPPORTED;
#endif

#if PN532_SAMPLE_ENABLE_DUMP
    if (!PN532_SAMPLE_ENABLE_NDEF || (ndef_res != NDEF_OK && ndef_res != NDEF_ERR_READ_FAILED)) {
        ESP_LOGI(TAG, "--- Card %d block dump ---", index + 1);
        pn532_dump_card(pn532, &working_uid);
    } else if (ndef_res == NDEF_ERR_READ_FAILED) {
        ESP_LOGI(TAG, "Skipping block dump after read failure");
    }
#endif
}

static void pn532_process_all_cards(pn532_t *pn532, const pn532_uids_array_t *uids)
{
    int count;

    if (pn532 == NULL || uids == NULL) {
        return;
    }

    count = uids->uids_count;
    if (count > PN532_SAMPLE_MAX_UIDS) {
        count = PN532_SAMPLE_MAX_UIDS;
    }

    for (int i = 0; i < count; i++) {
        /* get_all_uids leaves only the first card selected on PN532. Reselect
         * additional cards on demand, mirroring the PN5180 example's
         * select-if-needed flow. */
        pn532_process_card(pn532, &uids->uids[i], i, i != 0 || pn532->inListedTag == 0);
    }
}

void app_main(void)
{
    pn532_bus_t *bus = pn532_spi_init(PN532_SPI_HOST_ID, PN532_PIN_SCK, PN532_PIN_MISO, PN532_PIN_MOSI, PN532_PIN_NSS,
                                      PN532_SPI_CLOCK_HZ);
    if (bus == NULL) {
        ESP_LOGE(TAG, "PN532 SPI bus init failed");
        return;
    }

    pn532_t *pn532 = pn532_init(bus, PN532_PIN_IRQ, PN532_PIN_RST);
    if (pn532 == NULL) {
        ESP_LOGE(TAG, "PN532 init failed");
        pn532_bus_destroy(bus);
        return;
    }

    uint32_t firmware = pn532_get_firmware_version(pn532);
    if (firmware == 0) {
        ESP_LOGE(TAG, "PN532 firmware read failed");
        pn532_deinit(pn532, true);
        return;
    }

    ESP_LOGI(TAG, "PN532 SPI sample ready");
    ESP_LOGI(TAG, "Firmware: IC=0x%02" PRIX32 " Ver=%" PRIu32 ".%" PRIu32 " Support=0x%02" PRIX32,
             (firmware >> 24) & 0xFFu, (firmware >> 16) & 0xFFu, (firmware >> 8) & 0xFFu, firmware & 0xFFu);

    ESP_LOGI(TAG, "Polling ISO14443A cards over SPI");
    ESP_LOGI(TAG, "Tap a card to print its UID");

    pn532_uid_t last_uids[PN532_SAMPLE_MAX_UIDS] = {0};
    int         last_uids_count                  = 0;

    for (;;) {
        pn532_uids_array_t *uids = pn532_14443_get_all_uids(pn532);

        if (uids == NULL) {
            if (last_uids_count != 0) {
                ESP_LOGI(TAG, "No ISO14443A cards detected");
                pn532_copy_uids_snapshot(NULL, last_uids, &last_uids_count);
            }
            pn532_delay_ms(PN532_SAMPLE_POLL_MS);
            continue;
        }

        if (!pn532_uids_match(uids, last_uids, last_uids_count)) {
            pn532_log_detected_cards(uids);
            pn532_process_all_cards(pn532, uids);
            ESP_LOGI(TAG, "Card processing complete; remove card or tap a different one");
            pn532_copy_uids_snapshot(uids, last_uids, &last_uids_count);
        }

        free(uids);
        pn532_delay_ms(PN532_SAMPLE_POLL_MS);
    }
}
