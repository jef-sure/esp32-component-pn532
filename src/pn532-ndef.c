/**
 * @file pn532-ndef.c
 * @brief NDEF read/parse for cards selected through the PN532.
 *
 * Adapted from the jef-sure pn5180 NDEF implementation. Supports Type 1/2
 * (Ultralight, NTAG), Mifare Classic NDEF mapping, and Type 4 (DESFire/
 * ISO-DEP) via the PN532's built-in T=CL handler.
 */

#include "pn532-ndef.h"
#include "pn532-internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "pn532-mifare.h"

static const char *TAG = "PN532-NDEF";

static void pn532_type2_refine_uid_from_cc_read(const uint8_t *data, pn532_uid_t *uid)
{
    if (data == NULL || uid == NULL || data[0] != 0xE1) {
        return;
    }
    uid->block_size = 4;
    switch (data[2]) {
    case 0x06:
        uid->subtype      = PN532_MIFARE_ULTRALIGHT;
        uid->blocks_count = 16;
        break;
    case 0x12:
        uid->subtype      = PN532_MIFARE_NTAG213;
        uid->blocks_count = 45;
        break;
    case 0x3E:
        uid->subtype      = PN532_MIFARE_NTAG215;
        uid->blocks_count = 135;
        break;
    case 0x6D:
        uid->subtype      = PN532_MIFARE_NTAG216;
        uid->blocks_count = 231;
        break;
    default:
        break;
    }
}

static bool pn532_type2_prepare_layout(pn532_t *pn532, pn532_uid_t *uid)
{
    uint8_t cc_read[16];

    if (pn532 == NULL || uid == NULL) {
        return false;
    }

    if (pn532->inListedTag == 0) {
        if (!pn532_14443_select_by_uid(pn532, uid)) {
            return false;
        }
    } else if (!pn532->session_opened) {
        if (!pn532_in_select(pn532, pn532->inListedTag)) {
            if (!pn532_14443_select_by_uid(pn532, uid)) {
                return false;
            }
        }
    }

    if (!pn532_mifare_block_read(pn532, 3, cc_read, sizeof(cc_read))) {
        if (!pn532_14443_select_by_uid(pn532, uid)) {
            return false;
        }
        if (!pn532_mifare_block_read(pn532, 3, cc_read, sizeof(cc_read))) {
            return false;
        }
    }

    pn532_type2_refine_uid_from_cc_read(cc_read, uid);
    return true;
}

/* ---- TLV ---- */

#define TLV_NULL       0x00
#define TLV_NDEF       0x03
#define TLV_TERMINATOR 0xFE

typedef bool (*ndef_auth_callback_t)(pn532_t *pn532, int blockno, void *user_ctx);
typedef int (*ndef_sector_id_callback_t)(int blockno, void *user_ctx);

static size_t tlv_parse_length(const uint8_t *data, size_t data_len, size_t offset, size_t *value_offset)
{
    if (offset >= data_len) {
        *value_offset = 0;
        return 0;
    }
    if (data[offset] == 0xFF) {
        if (offset + 3 > data_len) {
            *value_offset = 0;
            return 0;
        }
        *value_offset = offset + 3;
        return ((size_t)data[offset + 1] << 8) | data[offset + 2];
    }
    *value_offset = offset + 1;
    return data[offset];
}

static bool ndef_tlv_find_ndef(const uint8_t *data, size_t data_len, size_t *search_pos, size_t *ndef_offset,
                               size_t *ndef_length)
{
    if (data == NULL || search_pos == NULL || ndef_offset == NULL || ndef_length == NULL) {
        return false;
    }

    size_t i = *search_pos;
    while (i < data_len) {
        uint8_t type = data[i];

        if (type == TLV_NULL) {
            i++;
            continue;
        }
        if (type == TLV_TERMINATOR) {
            *search_pos = i;
            return false;
        }

        if (i + 1 >= data_len) {
            *search_pos = i;
            return false;
        }

        size_t value_offset;
        size_t length = tlv_parse_length(data, data_len, i + 1, &value_offset);

        if (value_offset == 0) {
            *search_pos = i;
            return false;
        }

        if (type == TLV_NDEF) {
            *ndef_offset = value_offset;
            *ndef_length = length;
            *search_pos  = i;
            return true;
        }

        if (value_offset + length > data_len) {
            *search_pos = i;
            return false;
        }

        i = value_offset + length;
    }
    *search_pos = i;
    return false;
}

/* ---- URI prefix table ---- */

static const char *const uri_prefix_table[] = {
    "",                           /* 0x00 */
    "http://www.",                /* 0x01 */
    "https://www.",               /* 0x02 */
    "http://",                    /* 0x03 */
    "https://",                   /* 0x04 */
    "tel:",                       /* 0x05 */
    "mailto:",                    /* 0x06 */
    "ftp://anonymous:anonymous@", /* 0x07 */
    "ftp://ftp.",                 /* 0x08 */
    "ftps://",                    /* 0x09 */
    "sftp://",                    /* 0x0A */
    "smsto:",                     /* 0x0B */
    "sms:",                       /* 0x0C */
    "mms:",                       /* 0x0D */
    "mmsto:",                     /* 0x0E */
    "_ndef/_rtd_",                /* 0x0F */
    "_ndef/_urn_",                /* 0x10 */
    "_ndef/_pop_",                /* 0x11 */
    "_ndef/_sip_",                /* 0x12 */
    "geo:",                       /* 0x13 */
    "magnet:?",                   /* 0x14 */
    "urn:",                       /* 0x15 */
    "urn:epc:id:",                /* 0x16 */
    "urn:epc:tag:",               /* 0x17 */
    "urn:epc:pat:",               /* 0x18 */
    "urn:epc:raw:",               /* 0x19 */
    "urn:epc:",                   /* 0x1A */
    "urn:nfc:",                   /* 0x1B */
};
#define URI_PREFIX_COUNT (sizeof(uri_prefix_table) / sizeof(uri_prefix_table[0]))

/* ---- Record decoding ---- */

#define NDEF_MB       (1u << 7)
#define NDEF_ME       (1u << 6)
#define NDEF_CF       (1u << 5)
#define NDEF_SR       (1u << 4)
#define NDEF_IL       (1u << 3)
#define NDEF_TNF_MASK (0x07u)

static bool ndef_decode_next(const uint8_t *in, size_t in_len, size_t *offset, ndef_record_t *out_rec, bool *is_begin,
                             bool *is_end)
{
    if (in == NULL || offset == NULL || out_rec == NULL) {
        return false;
    }
    if (*offset >= in_len) {
        return false;
    }

    size_t     pos = *offset;
    uint8_t    hdr = in[pos++];
    bool       mb  = (hdr & NDEF_MB) != 0;
    bool       me  = (hdr & NDEF_ME) != 0;
    bool       sr  = (hdr & NDEF_SR) != 0;
    bool       il  = (hdr & NDEF_IL) != 0;
    ndef_tnf_t tnf = (ndef_tnf_t)(hdr & NDEF_TNF_MASK);

    if (pos >= in_len) {
        return false;
    }
    uint8_t type_len = in[pos++];

    uint32_t payload_len = 0;
    if (sr) {
        if (pos >= in_len) {
            return false;
        }
        payload_len = in[pos++];
    } else {
        if (pos + 4 > in_len) {
            return false;
        }
        payload_len = ((uint32_t)in[pos] << 24) | ((uint32_t)in[pos + 1] << 16) | ((uint32_t)in[pos + 2] << 8) |
                      (uint32_t)in[pos + 3];
        pos += 4;
    }

    uint8_t id_len = 0;
    if (il) {
        if (pos >= in_len) {
            return false;
        }
        id_len = in[pos++];
    }

    const uint8_t *type_ptr = NULL;
    if (type_len > 0) {
        if (pos + type_len > in_len) {
            return false;
        }
        type_ptr = &in[pos];
        pos += type_len;
    }

    const uint8_t *id_ptr = NULL;
    if (id_len > 0) {
        if (pos + id_len > in_len) {
            return false;
        }
        id_ptr = &in[pos];
        pos += id_len;
    }

    const uint8_t *payload_ptr = NULL;
    if (payload_len > 0) {
        if ((size_t)pos + payload_len > in_len) {
            return false;
        }
        payload_ptr = &in[pos];
        pos += payload_len;
    }

    out_rec->tnf         = tnf;
    out_rec->type_len    = type_len;
    out_rec->id_len      = id_len;
    out_rec->payload_len = payload_len;
    out_rec->type        = type_ptr;
    out_rec->id          = id_ptr;
    out_rec->payload     = payload_ptr;

    if (is_begin) {
        *is_begin = mb;
    }
    if (is_end) {
        *is_end = me;
    }
    *offset = pos;
    return true;
}

static size_t ndef_decode_message(const uint8_t *in, size_t in_len, ndef_record_t *records, size_t capacity)
{
    if (in == NULL || records == NULL || capacity == 0) {
        return 0;
    }
    size_t pos   = 0;
    size_t count = 0;
    while (count < capacity) {
        bool me = false;
        if (!ndef_decode_next(in, in_len, &pos, &records[count], NULL, &me)) {
            return 0;
        }
        count++;
        if (me) {
            break;
        }
        if (pos >= in_len) {
            break;
        }
    }
    return count;
}

static size_t ndef_count_records(const uint8_t *data, size_t data_len)
{
    size_t        count = 0;
    size_t        pos   = 0;
    ndef_record_t rec;
    while (pos < data_len) {
        bool me = false;
        if (!ndef_decode_next(data, data_len, &pos, &rec, NULL, &me)) {
            break;
        }
        count++;
        if (me) {
            break;
        }
    }
    return count;
}

/* ---- Read flow ---- */

#define NDEF_DEFAULT_MAX_BLOCKS 256

static bool classic_is_trailer_block(int blockno);

static ndef_result_t ndef_read_from_selected_card(  //
    pn532_t                  *pn532,                //
    int                       start_block,          //
    int                       block_size,           //
    int                       max_blocks,           //
    ndef_auth_callback_t      auth_cb,              //
    ndef_sector_id_callback_t sector_cb,            //
    void *user_ctx, ndef_message_parsed_t **out_msg //
)
{
    if (pn532 == NULL || out_msg == NULL || block_size <= 0 || block_size > 16) {
        return NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;

    int block_limit = (max_blocks > 0) ? max_blocks : NDEF_DEFAULT_MAX_BLOCKS;

    /* Grow-from-small buffer; pn532 has limited RAM. */
    size_t   capacity = 256;
    uint8_t *buf      = malloc(capacity);
    if (buf == NULL) {
        return NDEF_ERR_NO_MEMORY;
    }

    size_t len              = 0;
    size_t tlv_pos          = 0;
    size_t ndef_offset      = 0;
    size_t ndef_len         = 0;
    bool   found            = false;
    bool   read_ok          = true;
    bool   have_last_sector = false;
    int    last_sector_id   = 0;

    /*
     * Type 2 layout (Ultralight/NTAG): pn532 READ returns 16 bytes (4 pages)
     * starting at the requested page. We step in groups of 4 pages so we get
     * one transaction per 16 bytes of NDEF data.
     */
    int     read_stride = (block_size == 4) ? 4 : 1;
    uint8_t scratch[16];

    for (int block = start_block; (block - start_block) < block_limit; block += read_stride) {
        if (read_stride == 1 && sector_cb != NULL && classic_is_trailer_block(block)) {
            continue;
        }

        size_t chunk = (size_t)(block_size * read_stride);
        if (len + chunk > capacity) {
            size_t new_cap = capacity * 2;
            while (new_cap < len + chunk) {
                new_cap *= 2;
            }
            uint8_t *new_buf = realloc(buf, new_cap);
            if (new_buf == NULL) {
                free(buf);
                return NDEF_ERR_NO_MEMORY;
            }
            buf      = new_buf;
            capacity = new_cap;
        }

        if (auth_cb != NULL) {
            bool call_auth = true;
            if (sector_cb != NULL) {
                int sector_id = sector_cb(block, user_ctx);
                if (have_last_sector && sector_id == last_sector_id) {
                    call_auth = false;
                } else {
                    have_last_sector = true;
                    last_sector_id   = sector_id;
                }
            }
            if (call_auth && !auth_cb(pn532, block, user_ctx)) {
                read_ok = false;
                break;
            }
        }

        if (read_stride == 4) {
            /* Type 2: one READ -> 16 bytes covering pages [block .. block+3]. */
            if (!pn532_mifare_block_read(pn532, block, scratch, sizeof(scratch))) {
                read_ok = false;
                break;
            }
            memcpy(buf + len, scratch, sizeof(scratch));
            len += sizeof(scratch);
        } else {
            /* Mifare Classic: one block per call. */
            if (!pn532_mifare_block_read(pn532, block, buf + len, (size_t)block_size)) {
                read_ok = false;
                break;
            }
            len += (size_t)block_size;
        }

        if (ndef_tlv_find_ndef(buf, len, &tlv_pos, &ndef_offset, &ndef_len)) {
            if (ndef_offset + ndef_len <= len) {
                found = true;
                break;
            }
        } else if (tlv_pos < len && buf[tlv_pos] == TLV_TERMINATOR) {
            /* TLV terminator means there is definitively no NDEF beyond this point. */
            break;
        }
    }

    if (!found || ndef_len == 0) {
        free(buf);
        return read_ok ? NDEF_ERR_NO_NDEF : NDEF_ERR_READ_FAILED;
    }

    size_t count = ndef_count_records(buf + ndef_offset, ndef_len);
    if (count == 0) {
        free(buf);
        return NDEF_ERR_PARSE_FAILED;
    }

    size_t records_size = sizeof(ndef_record_t) * count;
    size_t total_size   = sizeof(ndef_message_parsed_t) + records_size + ndef_len;

    uint8_t *block_ptr = malloc(total_size);
    if (block_ptr == NULL) {
        free(buf);
        return NDEF_ERR_NO_MEMORY;
    }

    ndef_message_parsed_t *result    = (ndef_message_parsed_t *)block_ptr;
    ndef_record_t         *records   = (ndef_record_t *)(block_ptr + sizeof(ndef_message_parsed_t));
    uint8_t               *ndef_data = block_ptr + sizeof(ndef_message_parsed_t) + records_size;

    memcpy(ndef_data, buf + ndef_offset, ndef_len);
    free(buf);

    if (ndef_decode_message(ndef_data, ndef_len, records, count) != count) {
        free(block_ptr);
        return NDEF_ERR_PARSE_FAILED;
    }

    result->raw_data     = ndef_data;
    result->raw_data_len = ndef_len;
    result->records      = records;
    result->record_count = count;
    *out_msg             = result;
    return NDEF_OK;
}

/* ---- Mifare Classic auth callback (default key A) ---- */

typedef struct
{
    const pn532_uid_t *uid;
    const uint8_t     *primary_key;
    const uint8_t     *secondary_key;
    uint8_t            key_type;
} default_auth_ctx_t;

#define CLASSIC_MAD1_FIRST_DATA_BLOCK  1
#define CLASSIC_MAD1_SECOND_DATA_BLOCK 2
#define CLASSIC_MAD1_ENTRY_COUNT       15

static bool classic_try_auth_with_key( //
    pn532_t           *pn532,          //
    const pn532_uid_t *uid,            //
    int                blockno,        //
    const uint8_t     *key,            //
    uint8_t            key_type        //
)
{
    if (pn532 == NULL || uid == NULL || key == NULL) {
        return false;
    }

    if (pn532->inListedTag == 0) {
        if (!pn532_14443_select_by_uid(pn532, uid)) {
            return false;
        }
    } else if (!pn532->session_opened) {
        if (!pn532_in_select(pn532, pn532->inListedTag) && !pn532_14443_select_by_uid(pn532, uid)) {
            return false;
        }
    }

    return pn532_14443_authenticate(pn532, key, key_type, uid, blockno);
}

static bool classic_read_mad1(pn532_t *pn532, const pn532_uid_t *uid, uint8_t mad[32])
{
    static const uint8_t key_mad[6]     = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    static const uint8_t key_default[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (pn532 == NULL || uid == NULL || mad == NULL) {
        return false;
    }

    if (!classic_try_auth_with_key(pn532, uid, CLASSIC_MAD1_FIRST_DATA_BLOCK, key_mad, MIFARE_CMD_AUTH_A)) {
        if (!classic_try_auth_with_key(pn532, uid, CLASSIC_MAD1_FIRST_DATA_BLOCK, key_default, MIFARE_CMD_AUTH_A)) {
            return false;
        }
    }

    if (!pn532_mifare_block_read(pn532, CLASSIC_MAD1_FIRST_DATA_BLOCK, mad, 16)) {
        return false;
    }
    if (!pn532_mifare_block_read(pn532, CLASSIC_MAD1_SECOND_DATA_BLOCK, mad + 16, 16)) {
        return false;
    }
    return true;
}

static bool classic_mad1_entry_is_ndef(const uint8_t mad[32], int entry)
{
    if (mad == NULL || entry < 0 || entry >= CLASSIC_MAD1_ENTRY_COUNT) {
        return false;
    }

    size_t  offset = 2u + (size_t)entry * 2u;
    uint8_t aid0   = mad[offset];
    uint8_t aid1   = mad[offset + 1u];
    return (aid0 == 0x03 && aid1 == 0xE1) || (aid0 == 0xE1 && aid1 == 0x03);
}

static bool classic_mad1_find_ndef_sector_range(const uint8_t mad[32], int *start_sector_out, int *sector_count_out)
{
    if (mad == NULL || start_sector_out == NULL || sector_count_out == NULL) {
        return false;
    }

    int first_entry = -1;
    int last_entry  = -1;

    for (int entry = 0; entry < CLASSIC_MAD1_ENTRY_COUNT; entry++) {
        if (!classic_mad1_entry_is_ndef(mad, entry)) {
            continue;
        }

        if (first_entry < 0) {
            first_entry = entry;
            last_entry  = entry;
            continue;
        }

        if (entry != last_entry + 1) {
            return false;
        }
        last_entry = entry;
    }

    if (first_entry < 0) {
        return false;
    }

    *start_sector_out = first_entry + 1;
    *sector_count_out = last_entry - first_entry + 1;
    return true;
}

static bool classic_is_trailer_block(int blockno)
{
    if (blockno < 0) {
        return false;
    }
    if (blockno < 128) {
        return (blockno % 4) == 3;
    }
    return ((blockno - 128) % 16) == 15;
}

static int classic_sector_cb(int blockno, void *user_ctx)
{
    (void)user_ctx;
    if (blockno < 128) {
        return blockno / 4;
    }
    return 32 + (blockno - 128) / 16;
}

static bool classic_auth_cb(pn532_t *pn532, int blockno, void *user_ctx)
{
    default_auth_ctx_t *ctx = (default_auth_ctx_t *)user_ctx;
    if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, ctx->uid)) {
        ESP_LOGD(TAG, "reselect failed at blk %d", blockno);
        return false;
    }

    if (pn532_14443_authenticate(pn532, ctx->primary_key, ctx->key_type, ctx->uid, blockno)) {
        return true;
    }

    if (ctx->secondary_key == NULL) {
        ESP_LOGD(TAG, "auth failed at blk %d", blockno);
        return false;
    }

    if (!pn532_14443_select_by_uid(pn532, ctx->uid)) {
        ESP_LOGD(TAG, "reselect failed at blk %d", blockno);
        return false;
    }

    if (pn532_14443_authenticate(pn532, ctx->secondary_key, ctx->key_type, ctx->uid, blockno)) {
        return true;
    }

    ESP_LOGD(TAG, "auth failed at blk %d", blockno);
    return false;
}

/* ---- Type 4 (DESFire / ISO-DEP) NDEF read ---- */

/*
 * Type 4 Tag NDEF mapping (NFC Forum T4T spec):
 *   1. SELECT NDEF Tag Application by AID D2 76 00 00 85 01 01.
 *   2. SELECT Capability Container file (FID = 0xE103).
 *   3. READ BINARY 15 bytes of CC. CC layout:
 *        [0..1]  CCLEN
 *        [2]     Mapping version (0x20 = v2.0, 0x10 = v1.0)
 *        [3..4]  MLe (max R-APDU data size)
 *        [5..6]  MLc (max C-APDU data size)
 *        [7]     NDEF File Control TLV tag = 0x04
 *        [8]     NDEF File Control TLV len = 0x06
 *        [9..10] NDEF File Identifier
 *        [11..12]NDEF max file size
 *        [13]    Read access (0x00 = free)
 *        [14]    Write access
 *   4. SELECT NDEF file by FID from CC.
 *   5. READ BINARY 2 bytes from offset 0 -> NLEN.
 *   6. READ BINARY NLEN bytes from offset 2 (chunked by MLe-2) -> NDEF message.
 */

static ndef_result_t ndef_read_type4(pn532_t *pn532, ndef_message_parsed_t **out_msg)
{
    static const uint8_t ndef_aid[]   = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    static const uint8_t cc_file_id[] = {0xE1, 0x03};

    if (!pn532_14443_4_select_file(pn532, ndef_aid, sizeof(ndef_aid))) {
        ESP_LOGD(TAG, "T4: SELECT NDEF AID failed");
        return (pn532->inListedTag == 0) ? NDEF_ERR_READ_FAILED : NDEF_ERR_NO_NDEF;
    }
    if (!pn532_14443_4_select_file(pn532, cc_file_id, sizeof(cc_file_id))) {
        ESP_LOGD(TAG, "T4: SELECT CC failed");
        return (pn532->inListedTag == 0) ? NDEF_ERR_READ_FAILED : NDEF_ERR_NO_NDEF;
    }

    uint8_t cc[15];
    size_t  cc_got = sizeof(cc);
    if (!pn532_14443_4_read_binary(pn532, 0, sizeof(cc), cc, &cc_got) || cc_got < 15) {
        ESP_LOGD(TAG, "T4: READ CC failed (%u bytes)", (unsigned)cc_got);
        return NDEF_ERR_READ_FAILED;
    }

    uint16_t mle            = ((uint16_t)cc[3] << 8) | cc[4];
    uint8_t  ndef_fid_be[2] = {cc[9], cc[10]};
    uint16_t max_ndef_size  = ((uint16_t)cc[11] << 8) | cc[12];
    if (cc[7] != 0x04 || cc[8] != 0x06 || max_ndef_size < 2) {
        ESP_LOGD(TAG, "T4: bad CC TLV (T=%02X L=%02X)", cc[7], cc[8]);
        return NDEF_ERR_PARSE_FAILED;
    }
    /* Cap chunk size: APDU response returns data + SW (2 bytes), and our READ BINARY
     * helper uses a 260-byte buffer. Le is one byte (max 0xFF) and the PN532 InDataExchange
     * buffer is 280; 250 is the safe limit. */
    uint16_t chunk_max = (mle == 0 || mle > 250) ? 250u : mle;
    if (chunk_max > 250) {
        chunk_max = 250;
    }

    if (!pn532_14443_4_select_file(pn532, ndef_fid_be, sizeof(ndef_fid_be))) {
        ESP_LOGD(TAG, "T4: SELECT NDEF file %02X%02X failed", ndef_fid_be[0], ndef_fid_be[1]);
        return (pn532->inListedTag == 0) ? NDEF_ERR_READ_FAILED : NDEF_ERR_NO_NDEF;
    }

    uint8_t nlen_buf[2];
    size_t  nlen_got = sizeof(nlen_buf);
    if (!pn532_14443_4_read_binary(pn532, 0, 2, nlen_buf, &nlen_got) || nlen_got < 2) {
        return NDEF_ERR_READ_FAILED;
    }
    uint16_t nlen = ((uint16_t)nlen_buf[0] << 8) | nlen_buf[1];
    if (nlen == 0 || nlen + 2 > max_ndef_size) {
        return NDEF_ERR_NO_NDEF;
    }

    uint8_t *raw = malloc(nlen);
    if (raw == NULL) {
        return NDEF_ERR_NO_MEMORY;
    }
    uint16_t read_off  = 2;
    uint16_t remaining = nlen;
    while (remaining > 0) {
        uint8_t want = (remaining > chunk_max) ? (uint8_t)chunk_max : (uint8_t)remaining;
        size_t  got  = want;
        if (!pn532_14443_4_read_binary(pn532, read_off, want, raw + (read_off - 2), &got) || got != want) {
            free(raw);
            return NDEF_ERR_READ_FAILED;
        }
        read_off += want;
        remaining -= want;
    }

    size_t count = ndef_count_records(raw, nlen);
    if (count == 0) {
        free(raw);
        return NDEF_ERR_PARSE_FAILED;
    }

    size_t   records_size = sizeof(ndef_record_t) * count;
    size_t   total_size   = sizeof(ndef_message_parsed_t) + records_size + nlen;
    uint8_t *block_ptr    = malloc(total_size);
    if (block_ptr == NULL) {
        free(raw);
        return NDEF_ERR_NO_MEMORY;
    }

    ndef_message_parsed_t *result    = (ndef_message_parsed_t *)block_ptr;
    ndef_record_t         *records   = (ndef_record_t *)(block_ptr + sizeof(ndef_message_parsed_t));
    uint8_t               *ndef_data = block_ptr + sizeof(ndef_message_parsed_t) + records_size;

    memcpy(ndef_data, raw, nlen);
    free(raw);

    if (ndef_decode_message(ndef_data, nlen, records, count) != count) {
        free(block_ptr);
        return NDEF_ERR_PARSE_FAILED;
    }

    result->raw_data     = ndef_data;
    result->raw_data_len = nlen;
    result->records      = records;
    result->record_count = count;
    *out_msg             = result;
    return NDEF_OK;
}

ndef_result_t pn532_ndef_read_card_auto(pn532_t *pn532, pn532_uid_t *uid, ndef_message_parsed_t **out_msg)
{
    if (pn532 == NULL || uid == NULL || out_msg == NULL) {
        return NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;

    switch (uid->subtype) {
    case PN532_MIFARE_ULTRALIGHT:
    case PN532_MIFARE_ULTRALIGHT_C:
    case PN532_MIFARE_ULTRALIGHT_EV1:
    case PN532_MIFARE_NTAG213:
    case PN532_MIFARE_NTAG215:
    case PN532_MIFARE_NTAG216: {
        if (!pn532_type2_prepare_layout(pn532, uid)) {
            return NDEF_ERR_READ_FAILED;
        }
        /* NDEF data starts at page 4, capability container at page 3. */
        ndef_result_t res = ndef_read_from_selected_card(
            pn532, 4, 4, (uid->blocks_count > 4) ? (uid->blocks_count - 4) : 60, NULL, NULL, NULL, out_msg);
        if (res == NDEF_ERR_READ_FAILED) {
            if (!pn532_14443_select_by_uid(pn532, uid)) {
                return res;
            }
            if (!pn532_type2_prepare_layout(pn532, uid)) {
                return res;
            }
            res = ndef_read_from_selected_card(pn532, 4, 4, (uid->blocks_count > 4) ? (uid->blocks_count - 4) : 60,
                                               NULL, NULL, NULL, out_msg);
        }
        return res;
    }

    case PN532_MIFARE_CLASSIC_1K:
    case PN532_MIFARE_CLASSIC_4K:
    case PN532_MIFARE_CLASSIC_MINI: {
        if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, uid)) {
            return NDEF_ERR_READ_FAILED;
        }
        static const uint8_t key_a_default[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t key_a_ndef[6]    = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
        default_auth_ctx_t   ctx              = {
                           .uid = uid, .primary_key = key_a_ndef, .secondary_key = key_a_default, .key_type = MIFARE_CMD_AUTH_A};
        int start_block = 4;
        int max_blocks  = (uid->blocks_count > 4) ? (uid->blocks_count - 4) : 60;

        if (uid->subtype == PN532_MIFARE_CLASSIC_1K) {
            uint8_t mad[32];
            int     ndef_sector = 0;
            int     ndef_sector_count = 0;

            if (!classic_read_mad1(pn532, uid, mad)) {
                return NDEF_ERR_NO_NDEF;
            }
            if (!classic_mad1_find_ndef_sector_range(mad, &ndef_sector, &ndef_sector_count)) {
                return NDEF_ERR_NO_NDEF;
            }

            start_block = ndef_sector * 4;
            max_blocks  = ndef_sector_count * 4;
            if (uid->blocks_count <= start_block || max_blocks <= 0 || start_block + max_blocks > uid->blocks_count) {
                return NDEF_ERR_NO_NDEF;
            }
        }

        ndef_result_t res = ndef_read_from_selected_card(pn532, start_block, 16, max_blocks, classic_auth_cb,
                                                         classic_sector_cb, &ctx, out_msg);
        return res;
    }

    case PN532_MIFARE_DESFIRE:
        if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, uid)) {
            return NDEF_ERR_READ_FAILED;
        }
        ndef_result_t res = ndef_read_type4(pn532, out_msg);
        if (res == NDEF_ERR_READ_FAILED) {
            pn532_delay_ms(10);
            if (pn532->inListedTag == 0) {
                if (!pn532_14443_select_by_uid(pn532, uid)) {
                    return res;
                }
            }
            res = ndef_read_type4(pn532, out_msg);
        }
        return res;

    default:
        return NDEF_ERR_UNSUPPORTED;
    }
}

void ndef_free_parsed_message(ndef_message_parsed_t *msg)
{
    free(msg);
}

/* ---- Record helpers ---- */

bool ndef_extract_text(const ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out, char *lang_buf,
                       bool *is_utf16)
{
    if (rec == NULL || text_out == NULL || text_len_out == NULL) {
        return false;
    }
    if (rec->tnf != NDEF_TNF_WELL_KNOWN || rec->type_len != 1 || rec->type == NULL || rec->type[0] != 'T') {
        return false;
    }
    if (rec->payload == NULL || rec->payload_len < 1) {
        return false;
    }

    uint8_t status   = rec->payload[0];
    size_t  lang_len = (size_t)(status & 0x3F);
    bool    utf16    = (status & 0x80) != 0;
    if (1 + lang_len > rec->payload_len) {
        return false;
    }

    if (lang_buf != NULL) {
        if (lang_len > 0) {
            memcpy(lang_buf, rec->payload + 1, lang_len);
        }
        lang_buf[lang_len] = '\0';
    }
    if (is_utf16 != NULL) {
        *is_utf16 = utf16;
    }
    *text_out     = rec->payload + 1 + lang_len;
    *text_len_out = rec->payload_len - 1 - lang_len;
    return true;
}

size_t ndef_extract_uri(const ndef_record_t *rec, char *uri_buf, size_t uri_buf_len)
{
    if (rec == NULL) {
        return 0;
    }
    if (rec->tnf != NDEF_TNF_WELL_KNOWN || rec->type_len != 1 || rec->type == NULL || rec->type[0] != 'U') {
        return 0;
    }
    if (rec->payload == NULL || rec->payload_len < 1) {
        return 0;
    }

    uint8_t     code       = rec->payload[0];
    const char *prefix     = (code < URI_PREFIX_COUNT) ? uri_prefix_table[code] : "";
    size_t      prefix_len = strlen(prefix);
    size_t      suffix_len = rec->payload_len - 1;
    size_t      total_len  = prefix_len + suffix_len;

    if (uri_buf != NULL && uri_buf_len > 0) {
        size_t copy_prefix = (prefix_len < uri_buf_len - 1) ? prefix_len : uri_buf_len - 1;
        memcpy(uri_buf, prefix, copy_prefix);

        size_t remaining   = uri_buf_len - 1 - copy_prefix;
        size_t copy_suffix = (suffix_len < remaining) ? suffix_len : remaining;
        if (copy_suffix > 0) {
            memcpy(uri_buf + copy_prefix, rec->payload + 1, copy_suffix);
        }
        uri_buf[copy_prefix + copy_suffix] = '\0';
    }
    return total_len;
}

ndef_record_type_t ndef_get_record_type(const ndef_record_t *rec)
{
    if (rec == NULL) {
        return NDEF_RECORD_TYPE_UNKNOWN;
    }
    if (rec->tnf == NDEF_TNF_EMPTY) {
        return NDEF_RECORD_TYPE_EMPTY;
    }
    if (rec->tnf == NDEF_TNF_MEDIA_TYPE) {
        return NDEF_RECORD_TYPE_MIME;
    }
    if (rec->tnf == NDEF_TNF_EXTERNAL) {
        return NDEF_RECORD_TYPE_EXTERNAL;
    }
    if (rec->tnf == NDEF_TNF_WELL_KNOWN && rec->type != NULL && rec->type_len > 0) {
        if (rec->type_len == 1 && rec->type[0] == 'T') {
            return NDEF_RECORD_TYPE_TEXT;
        }
        if (rec->type_len == 1 && rec->type[0] == 'U') {
            return NDEF_RECORD_TYPE_URI;
        }
        if (rec->type_len == 2 && rec->type[0] == 'S' && rec->type[1] == 'p') {
            return NDEF_RECORD_TYPE_SMARTPOSTER;
        }
    }
    return NDEF_RECORD_TYPE_UNKNOWN;
}

bool ndef_record_is_text(const ndef_record_t *rec)
{
    return ndef_get_record_type(rec) == NDEF_RECORD_TYPE_TEXT;
}
bool ndef_record_is_uri(const ndef_record_t *rec)
{
    return ndef_get_record_type(rec) == NDEF_RECORD_TYPE_URI;
}
bool ndef_record_is_smartposter(const ndef_record_t *rec)
{
    return ndef_get_record_type(rec) == NDEF_RECORD_TYPE_SMARTPOSTER;
}

size_t ndef_decode_smartposter(const ndef_record_t *rec, ndef_record_t *records, size_t capacity)
{
    if (!ndef_record_is_smartposter(rec) || rec->payload == NULL || rec->payload_len == 0) {
        return 0;
    }
    return ndef_decode_message(rec->payload, rec->payload_len, records, capacity);
}

const char *ndef_result_to_string(ndef_result_t result)
{
    switch (result) {
    case NDEF_OK:
        return "OK";
    case NDEF_ERR_INVALID_PARAM:
        return "Invalid parameter";
    case NDEF_ERR_NO_MEMORY:
        return "Out of memory";
    case NDEF_ERR_READ_FAILED:
        return "Card read failed";
    case NDEF_ERR_WRITE_FAILED:
        return "Card write failed";
    case NDEF_ERR_NO_NDEF:
        return "No NDEF data found";
    case NDEF_ERR_PARSE_FAILED:
        return "NDEF parse failed";
    case NDEF_ERR_BUFFER_TOO_SMALL:
        return "Buffer too small";
    case NDEF_ERR_CARD_FULL:
        return "Card capacity exceeded";
    case NDEF_ERR_UNSUPPORTED:
        return "Unsupported card";
    default:
        return "Unknown";
    }
}
