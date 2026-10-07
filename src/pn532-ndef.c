/**
 * @file pn532-ndef.c
 * @brief NDEF read/parse for cards selected through the PN532.
 *
 * Adapted from the jef-sure pn5180 NDEF implementation. Supports Type 2
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

const uint8_t PN532_NDEF_RTD_TEXT[]        = {'T'};
const uint8_t PN532_NDEF_RTD_URI[]         = {'U'};
const uint8_t PN532_NDEF_RTD_SMARTPOSTER[] = {'S', 'p'};

/* Returns false when page 3 does not hold a capability container. */
static bool pn532_type2_refine_uid_from_cc_read(const uint8_t *data, pn532_uid_t *uid)
{
    if (data == NULL || uid == NULL || data[0] != 0xE1) {
        return false;
    }
    uid->block_size = 4;
    /* CC[2] is the size of the NDEF data area in units of 8 bytes
     * (NTAG/Ultralight CC layout, NFC Forum Type 2 Tag ODS). It excludes
     * page 0..3 and the lock/config pages, so it — not the physical page
     * count — bounds how far NDEF reads may go. */
    uint16_t data_area_pages = (uint16_t)data[2] * 2u;
    uid->blocks_count        = (uint16_t)(4u + data_area_pages);
    /* The size only hints at the chip: a subtype the card itself reported
     * (pn532_14443_detect_selected_card_type_and_capacity()) is kept. */
    if (uid->subtype != PN532_MIFARE_ULTRALIGHT) {
        return true;
    }
    switch (data[2]) {
    case 0x06:
        uid->subtype = PN532_MIFARE_ULTRALIGHT;
        break;
    case 0x12:
        uid->subtype = PN532_MIFARE_NTAG213;
        break;
    case 0x3E:
        uid->subtype = PN532_MIFARE_NTAG215;
        break;
    case 0x6D:
        uid->subtype = PN532_MIFARE_NTAG216;
        break;
    default:
        break;
    }
    return true;
}

/* *has_cc reports whether the tag carries a capability container; without
 * one it is not NDEF formatted and uid is left as detected from the SAK. */
static bool pn532_type2_prepare_layout(pn532_t *pn532, pn532_uid_t *uid, bool *has_cc)
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
        if (pn532->tg_stale || !pn532_in_select(pn532, pn532->inListedTag)) {
            if (!pn532_14443_select_by_uid(pn532, uid)) {
                return false;
            }
        }
    }

    if (!pn532_14443_block_read(pn532, 3, cc_read, sizeof(cc_read))) {
        if (!pn532_14443_select_by_uid(pn532, uid)) {
            return false;
        }
        if (!pn532_14443_block_read(pn532, 3, cc_read, sizeof(cc_read))) {
            return false;
        }
    }

    *has_cc = pn532_type2_refine_uid_from_cc_read(cc_read, uid);
    return true;
}

/* ---- TLV ---- */

#define TLV_NULL       0x00
#define TLV_NDEF       0x03
#define TLV_TERMINATOR 0xFE

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

/* NFC Forum URI RTD 1.0, table 3: URI identifier codes. */
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
    "smb://",                     /* 0x0B */
    "nfs://",                     /* 0x0C */
    "ftp://",                     /* 0x0D */
    "dav://",                     /* 0x0E */
    "news:",                      /* 0x0F */
    "telnet://",                  /* 0x10 */
    "imap:",                      /* 0x11 */
    "rtsp://",                    /* 0x12 */
    "urn:",                       /* 0x13 */
    "pop:",                       /* 0x14 */
    "sip:",                       /* 0x15 */
    "sips:",                      /* 0x16 */
    "tftp:",                      /* 0x17 */
    "btspp://",                   /* 0x18 */
    "btl2cap://",                 /* 0x19 */
    "btgoep://",                  /* 0x1A */
    "tcpobex://",                 /* 0x1B */
    "irdaobex://",                /* 0x1C */
    "file://",                    /* 0x1D */
    "urn:epc:id:",                /* 0x1E */
    "urn:epc:tag:",               /* 0x1F */
    "urn:epc:pat:",               /* 0x20 */
    "urn:epc:raw:",               /* 0x21 */
    "urn:epc:",                   /* 0x22 */
    "urn:nfc:",                   /* 0x23 */
};
#define URI_PREFIX_COUNT (sizeof(uri_prefix_table) / sizeof(uri_prefix_table[0]))

/* ---- Record decoding ---- */

#define NDEF_MB       (1u << 7)
#define NDEF_ME       (1u << 6)
#define NDEF_CF       (1u << 5)
#define NDEF_SR       (1u << 4)
#define NDEF_IL       (1u << 3)
#define NDEF_TNF_MASK (0x07u)

static bool ndef_decode_next(const uint8_t *in, size_t in_len, size_t *offset, pn532_ndef_record_t *out_rec,
                             bool *is_begin, bool *is_end, bool *is_chunk)
{
    if (in == NULL || offset == NULL || out_rec == NULL) {
        return false;
    }
    if (*offset >= in_len) {
        return false;
    }

    size_t           pos = *offset;
    uint8_t          hdr = in[pos++];
    bool             mb  = (hdr & NDEF_MB) != 0;
    bool             me  = (hdr & NDEF_ME) != 0;
    bool             sr  = (hdr & NDEF_SR) != 0;
    bool             il  = (hdr & NDEF_IL) != 0;
    pn532_ndef_tnf_t tnf = (pn532_ndef_tnf_t)(hdr & NDEF_TNF_MASK);

    if (tnf == PN532_NDEF_TNF_RESERVED) {
        /* NFC RTD: TNF 0x07 is reserved and must not appear in a message. */
        return false;
    }

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
        if (in_len - pos < 4) {
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
        if (type_len > in_len - pos) {
            return false;
        }
        type_ptr = &in[pos];
        pos += type_len;
    }

    const uint8_t *id_ptr = NULL;
    if (id_len > 0) {
        if (id_len > in_len - pos) {
            return false;
        }
        id_ptr = &in[pos];
        pos += id_len;
    }

    const uint8_t *payload_ptr = NULL;
    if (payload_len > 0) {
        /* Subtraction form: pos + payload_len wraps a 32-bit size_t. */
        if (payload_len > in_len - pos) {
            return false;
        }
        payload_ptr = &in[pos];
        pos += payload_len;
    }

    if (tnf == PN532_NDEF_TNF_UNKNOWN && type_len != 0) {
        /* NDEF 1.0 §3.2.6: an unknown-type record carries no type (Android
         * rejects it the same way). */
        return false;
    }

    if (tnf == PN532_NDEF_TNF_EMPTY && (type_len != 0 || id_len != 0 || payload_len != 0)) {
        /* NFC RTD: an empty record must carry no type, ID, or payload. */
        return false;
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
    if (is_chunk) {
        *is_chunk = (hdr & NDEF_CF) != 0;
    }
    *offset = pos;
    return true;
}

static size_t ndef_decode_message(const uint8_t *in, size_t in_len, pn532_ndef_record_t *records, size_t capacity)
{
    if (in == NULL || records == NULL || capacity == 0) {
        return 0;
    }
    size_t pos   = 0;
    size_t count = 0;
    while (count < capacity) {
        bool me = false;
        if (!ndef_decode_next(in, in_len, &pos, &records[count], NULL, &me, NULL)) {
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

static bool ndef_size_add(size_t base, size_t add, size_t *out)
{
    if (out == NULL || add > (SIZE_MAX - base)) {
        return false;
    }
    *out = base + add;
    return true;
}

typedef struct
{
    size_t logical_record_count;
    size_t chunk_payload_size;
    bool   has_chunks;
} ndef_decode_plan_t;

static bool ndef_plan_decode(const uint8_t *data, size_t data_len, ndef_decode_plan_t *plan)
{
    if (data == NULL || data_len == 0 || plan == NULL) {
        return false;
    }

    memset(plan, 0, sizeof(*plan));
    size_t   pos             = 0;
    size_t   physical_count  = 0;
    uint32_t chunk_total_len = 0;
    bool     in_chunk        = false;
    bool     message_ended   = false;

    while (pos < data_len) {
        pn532_ndef_record_t physical;
        bool                mb = false;
        bool                me = false;
        bool                cf = false;
        if (!ndef_decode_next(data, data_len, &pos, &physical, &mb, &me, &cf)) {
            return false;
        }

        if ((physical_count == 0 && !mb) || (physical_count != 0 && mb) || message_ended) {
            return false;
        }
        physical_count++;

        if (in_chunk) {
            if (physical.tnf != PN532_NDEF_TNF_UNCHANGED || physical.type_len != 0 || physical.id_len != 0 ||
                (cf && me)) {
                return false;
            }
            if (physical.payload_len > UINT32_MAX - chunk_total_len ||
                !ndef_size_add(plan->chunk_payload_size, physical.payload_len, &plan->chunk_payload_size)) {
                return false;
            }
            chunk_total_len += physical.payload_len;
            if (!cf) {
                in_chunk = false;
                plan->logical_record_count++;
            }
        } else {
            if (physical.tnf == PN532_NDEF_TNF_UNCHANGED) {
                return false;
            }
            if (cf) {
                if (me) {
                    return false;
                }
                in_chunk         = true;
                plan->has_chunks = true;
                chunk_total_len  = physical.payload_len;
                if (!ndef_size_add(plan->chunk_payload_size, physical.payload_len, &plan->chunk_payload_size)) {
                    return false;
                }
            } else {
                plan->logical_record_count++;
            }
        }

        if (me) {
            if (in_chunk) {
                return false;
            }
            message_ended = true;
        }
    }

    return message_ended && !in_chunk && plan->logical_record_count > 0;
}

static bool ndef_decode_logical_records(uint8_t *data, size_t data_len, pn532_ndef_record_t *records,
                                        size_t record_count, uint8_t *chunk_payload)
{
    size_t               pos          = 0;
    size_t               logical      = 0;
    size_t               payload_used = 0;
    pn532_ndef_record_t *chunk_record = NULL;

    while (pos < data_len && logical < record_count) {
        pn532_ndef_record_t physical;
        bool                cf = false;
        if (!ndef_decode_next(data, data_len, &pos, &physical, NULL, NULL, &cf)) {
            return false;
        }

        if (chunk_record != NULL) {
            if (physical.payload_len > 0) {
                memcpy(chunk_payload + payload_used, physical.payload, physical.payload_len);
                payload_used += physical.payload_len;
                chunk_record->payload_len += physical.payload_len;
            }
            if (!cf) {
                logical++;
                chunk_record = NULL;
            }
        } else if (cf) {
            records[logical]             = physical;
            records[logical].payload     = chunk_payload + payload_used;
            records[logical].payload_len = 0;
            chunk_record                 = &records[logical];
            if (physical.payload_len > 0) {
                memcpy(chunk_payload + payload_used, physical.payload, physical.payload_len);
                payload_used += physical.payload_len;
                chunk_record->payload_len = physical.payload_len;
            }
        } else {
            records[logical++] = physical;
        }
    }

    return logical == record_count && chunk_record == NULL;
}

pn532_ndef_result_t pn532_ndef_parse_message(const uint8_t *raw_data, size_t raw_data_len,
                                             pn532_ndef_message_parsed_t **out_msg)
{
    if (raw_data == NULL || raw_data_len == 0 || out_msg == NULL) {
        return PN532_NDEF_ERR_PARSE_FAILED;
    }

    ndef_decode_plan_t plan;
    if (!ndef_plan_decode(raw_data, raw_data_len, &plan)) {
        return PN532_NDEF_ERR_PARSE_FAILED;
    }

    if (plan.logical_record_count > SIZE_MAX / sizeof(pn532_ndef_record_t)) {
        return PN532_NDEF_ERR_NO_MEMORY;
    }
    size_t records_size = sizeof(pn532_ndef_record_t) * plan.logical_record_count;
    size_t total_size;
    if (!ndef_size_add(sizeof(pn532_ndef_message_parsed_t), records_size, &total_size) ||
        !ndef_size_add(total_size, raw_data_len, &total_size) ||
        !ndef_size_add(total_size, plan.chunk_payload_size, &total_size)) {
        return PN532_NDEF_ERR_NO_MEMORY;
    }

    uint8_t *block_ptr = malloc(total_size);
    if (block_ptr == NULL) {
        return PN532_NDEF_ERR_NO_MEMORY;
    }

    pn532_ndef_message_parsed_t *result    = (pn532_ndef_message_parsed_t *)block_ptr;
    pn532_ndef_record_t         *records   = (pn532_ndef_record_t *)(block_ptr + sizeof(pn532_ndef_message_parsed_t));
    uint8_t                     *ndef_data = block_ptr + sizeof(pn532_ndef_message_parsed_t) + records_size;
    uint8_t                     *chunk_payload = ndef_data + raw_data_len;

    memcpy(ndef_data, raw_data, raw_data_len);
    if (!ndef_decode_logical_records(ndef_data, raw_data_len, records, plan.logical_record_count, chunk_payload)) {
        free(block_ptr);
        return PN532_NDEF_ERR_PARSE_FAILED;
    }

    result->raw_data     = ndef_data;
    result->raw_data_len = raw_data_len;
    result->records      = records;
    result->record_count = plan.logical_record_count;
    *out_msg             = result;
    return PN532_NDEF_OK;
}

void pn532_ndef_message_init(pn532_ndef_message_t *msg, pn532_ndef_record_t *records, size_t capacity)
{
    if (msg == NULL) {
        return;
    }
    msg->records      = records;
    msg->record_count = 0;
    msg->capacity     = capacity;
}

bool pn532_ndef_message_add(pn532_ndef_message_t *msg, const pn532_ndef_record_t *rec)
{
    if (msg == NULL || rec == NULL || msg->record_count >= msg->capacity) {
        return false;
    }
    msg->records[msg->record_count++] = *rec;
    return true;
}

void pn532_ndef_record_init(pn532_ndef_record_t *rec, pn532_ndef_tnf_t tnf, const uint8_t *type, uint8_t type_len,
                            const uint8_t *id, uint8_t id_len, const uint8_t *payload, uint32_t payload_len)
{
    if (rec == NULL) {
        return;
    }
    rec->tnf         = tnf;
    rec->type_len    = type_len;
    rec->id_len      = id_len;
    rec->payload_len = payload_len;
    rec->type        = type;
    rec->id          = id;
    rec->payload     = payload;
}

static bool ndef_record_has_consistent_storage(const pn532_ndef_record_t *rec)
{
    if (rec == NULL) {
        return false;
    }

    return !((rec->type_len > 0 && rec->type == NULL) || (rec->id_len > 0 && rec->id == NULL) ||
             (rec->payload_len > 0 && rec->payload == NULL));
}

static bool ndef_record_encoded_size(const pn532_ndef_record_t *rec, size_t *size_out)
{
    if (rec == NULL || size_out == NULL) {
        return false;
    }

    if (!ndef_record_has_consistent_storage(rec)) {
        return false;
    }

    bool   short_record = rec->payload_len <= 255;
    size_t size         = 1;
    if (!ndef_size_add(size, 1, &size)) {
        return false;
    }
    if (!ndef_size_add(size, short_record ? 1u : 4u, &size)) {
        return false;
    }
    if (rec->id_len > 0) {
        if (!ndef_size_add(size, 1, &size)) {
            return false;
        }
    }
    if (!ndef_size_add(size, rec->type_len, &size) || !ndef_size_add(size, rec->id_len, &size) ||
        !ndef_size_add(size, rec->payload_len, &size)) {
        return false;
    }

    *size_out = size;
    return true;
}

static uint8_t ndef_build_header_byte(const pn532_ndef_record_t *rec, bool is_begin, bool is_end)
{
    uint8_t hdr = 0;

    if (is_begin) {
        hdr |= NDEF_MB;
    }
    if (is_end) {
        hdr |= NDEF_ME;
    }
    if (rec->payload_len <= 255) {
        hdr |= NDEF_SR;
    }
    if (rec->id_len > 0) {
        hdr |= NDEF_IL;
    }
    hdr |= (uint8_t)(rec->tnf & NDEF_TNF_MASK);
    return hdr;
}

size_t pn532_ndef_encode_message(const pn532_ndef_message_t *msg, uint8_t *out, size_t out_len)
{
    if (msg == NULL || (out == NULL && out_len > 0)) {
        return 0;
    }

    size_t required = 0;
    for (size_t i = 0; i < msg->record_count; i++) {
        size_t record_size = 0;
        if (!ndef_record_encoded_size(&msg->records[i], &record_size) ||
            !ndef_size_add(required, record_size, &required)) {
            return 0;
        }
    }
    if (out == NULL || out_len == 0) {
        return required;
    }
    if (out_len < required) {
        return 0;
    }

    uint8_t *cursor = out;
    for (size_t i = 0; i < msg->record_count; i++) {
        const pn532_ndef_record_t *rec          = &msg->records[i];
        bool                       is_begin     = (i == 0);
        bool                       is_end       = (i == (msg->record_count - 1));
        bool                       short_record = rec->payload_len <= 255;

        if (!ndef_record_has_consistent_storage(rec)) {
            return 0;
        }

        *cursor++ = ndef_build_header_byte(rec, is_begin, is_end);
        *cursor++ = rec->type_len;
        if (short_record) {
            *cursor++ = (uint8_t)rec->payload_len;
        } else {
            *cursor++ = (uint8_t)((rec->payload_len >> 24) & 0xFF);
            *cursor++ = (uint8_t)((rec->payload_len >> 16) & 0xFF);
            *cursor++ = (uint8_t)((rec->payload_len >> 8) & 0xFF);
            *cursor++ = (uint8_t)(rec->payload_len & 0xFF);
        }
        if (rec->id_len > 0) {
            *cursor++ = rec->id_len;
        }
        if (rec->type_len > 0) {
            memcpy(cursor, rec->type, rec->type_len);
            cursor += rec->type_len;
        }
        if (rec->id_len > 0) {
            memcpy(cursor, rec->id, rec->id_len);
            cursor += rec->id_len;
        }
        if (rec->payload_len > 0) {
            memcpy(cursor, rec->payload, rec->payload_len);
            cursor += rec->payload_len;
        }
    }

    return (size_t)(cursor - out);
}

/* Longest matching prefix wins, so "ftp://ftp." beats "ftp://" and
 * "urn:epc:id:" beats "urn:epc:" and "urn:". */
static uint8_t ndef_uri_prefix_code(const char *uri, size_t *prefix_len)
{
    uint8_t best_code = 0x00;
    size_t  best_len  = 0;

    for (size_t code = 1; code < URI_PREFIX_COUNT; code++) {
        size_t len = strlen(uri_prefix_table[code]);

        if (len > best_len && strncmp(uri, uri_prefix_table[code], len) == 0) {
            best_code = (uint8_t)code;
            best_len  = len;
        }
    }

    if (prefix_len != NULL) {
        *prefix_len = best_len;
    }
    return best_code;
}

bool pn532_ndef_make_text_record(pn532_ndef_record_t *rec, const char *lang_code, const uint8_t *text, size_t text_len,
                                 bool utf16, uint8_t *payload_buf, size_t payload_buf_len)
{
    if (rec == NULL || text == NULL || payload_buf == NULL) {
        return false;
    }

    size_t lang_len = (lang_code != NULL) ? strlen(lang_code) : 0;
    if (lang_len > 63) {
        return false;
    }

    size_t needed = 1 + lang_len + text_len;
    if (payload_buf_len < needed) {
        return false;
    }

    payload_buf[0] = (utf16 ? 0x80 : 0x00) | (uint8_t)lang_len;
    if (lang_len > 0 && lang_code != NULL) {
        memcpy(&payload_buf[1], lang_code, lang_len);
    }
    if (text_len > 0) {
        memcpy(&payload_buf[1 + lang_len], text, text_len);
    }

    pn532_ndef_record_init(rec, PN532_NDEF_TNF_WELL_KNOWN, PN532_NDEF_RTD_TEXT, PN532_NDEF_RTD_TEXT_LEN, NULL, 0,
                           payload_buf, (uint32_t)needed);
    return true;
}

bool pn532_ndef_make_uri_record(pn532_ndef_record_t *rec, const char *uri, bool abbreviate, uint8_t *payload_buf,
                                size_t payload_buf_len)
{
    if (rec == NULL || uri == NULL || payload_buf == NULL) {
        return false;
    }

    size_t  prefix_len    = 0;
    uint8_t prefix_code   = abbreviate ? ndef_uri_prefix_code(uri, &prefix_len) : 0x00;
    size_t  uri_len       = strlen(uri);
    size_t  remaining_len = uri_len - prefix_len;
    size_t  needed        = 1 + remaining_len;
    if (payload_buf_len < needed) {
        return false;
    }

    payload_buf[0] = prefix_code;
    memcpy(&payload_buf[1], uri + prefix_len, remaining_len);

    pn532_ndef_record_init(rec, PN532_NDEF_TNF_WELL_KNOWN, PN532_NDEF_RTD_URI, PN532_NDEF_RTD_URI_LEN, NULL, 0,
                           payload_buf, (uint32_t)needed);
    return true;
}

bool pn532_ndef_make_mime_record(pn532_ndef_record_t *rec, const char *mime_type, const uint8_t *data, size_t data_len,
                                 uint8_t *type_buf, size_t type_buf_len)
{
    if (rec == NULL || mime_type == NULL || type_buf == NULL) {
        return false;
    }

    size_t type_len = strlen(mime_type);
    if (type_len == 0 || type_len > 255 || type_len > type_buf_len) {
        return false;
    }

    memcpy(type_buf, mime_type, type_len);
    pn532_ndef_record_init(rec, PN532_NDEF_TNF_MEDIA_TYPE, type_buf, (uint8_t)type_len, NULL, 0, data,
                           (uint32_t)data_len);
    return true;
}

bool pn532_ndef_make_external_record(pn532_ndef_record_t *rec, const char *type_name, const uint8_t *data,
                                     size_t data_len, uint8_t *type_buf, size_t type_buf_len)
{
    if (rec == NULL || type_name == NULL || type_buf == NULL) {
        return false;
    }

    size_t type_len = strlen(type_name);
    if (type_len == 0 || type_len > 255 || type_len > type_buf_len) {
        return false;
    }

    memcpy(type_buf, type_name, type_len);
    pn532_ndef_record_init(rec, PN532_NDEF_TNF_EXTERNAL, type_buf, (uint8_t)type_len, NULL, 0, data,
                           (uint32_t)data_len);
    return true;
}

/* ---- Read flow ---- */

/*
 * Type 2 (Ultralight/NTAG) flat read: READ returns 16 bytes (4 pages) from the
 * requested page, so the TLV area is scanned 4 pages per transaction. MIFARE
 * Classic goes through classic_read_from_selected_sectors() instead.
 */
static pn532_ndef_result_t type2_read_ndef(pn532_t *pn532, int start_page, int max_pages,
                                           pn532_ndef_message_parsed_t **out_msg)
{
    if (pn532 == NULL || out_msg == NULL || max_pages <= 0) {
        return PN532_NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;

    /* Grow-from-small buffer; pn532 has limited RAM. */
    size_t   capacity = 256;
    uint8_t *buf      = malloc(capacity);
    if (buf == NULL) {
        return PN532_NDEF_ERR_NO_MEMORY;
    }

    size_t len         = 0;
    size_t tlv_pos     = 0;
    size_t ndef_offset = 0;
    size_t ndef_len    = 0;
    bool   found       = false;
    bool   read_ok     = true;

    for (int page = start_page; (page - start_page) < max_pages; page += 4) {
        if (len + 16 > capacity) {
            size_t   new_cap = capacity * 2;
            uint8_t *new_buf = realloc(buf, new_cap);
            if (new_buf == NULL) {
                free(buf);
                return PN532_NDEF_ERR_NO_MEMORY;
            }
            buf      = new_buf;
            capacity = new_cap;
        }

        if (!pn532_14443_block_read(pn532, page, buf + len, 16)) {
            read_ok = false;
            break;
        }
        /* The last READ of the data area may run into the lock/configuration
         * pages or wrap around to page 0, so only pages inside the area count. */
        int pages_left = max_pages - (page - start_page);
        len += (pages_left < 4) ? (size_t)pages_left * 4u : 16u;

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
        return read_ok ? PN532_NDEF_ERR_NO_NDEF : PN532_NDEF_ERR_READ_FAILED;
    }

    pn532_ndef_result_t parse_res = pn532_ndef_parse_message(buf + ndef_offset, ndef_len, out_msg);
    free(buf);
    return parse_res;
}

pn532_ndef_result_t pn532_ndef_write_to_selected_card(pn532_t *pn532, const pn532_ndef_message_t *msg, int start_block,
                                                      int block_size, int max_blocks)
{
    if (pn532 == NULL || msg == NULL || start_block < 0 || block_size <= 0) {
        return PN532_NDEF_ERR_INVALID_PARAM;
    }

    if (block_size != 4) {
        return PN532_NDEF_ERR_UNSUPPORTED;
    }

    size_t ndef_len = pn532_ndef_encode_message(msg, NULL, 0);
    if (ndef_len == 0) {
        return PN532_NDEF_ERR_INVALID_PARAM;
    }

    size_t tlv_len_bytes = (ndef_len < 0xFF) ? 1 : 3;
    size_t total_len     = 0;
    if (!ndef_size_add(1u, tlv_len_bytes, &total_len) || !ndef_size_add(total_len, ndef_len, &total_len) ||
        !ndef_size_add(total_len, 1u, &total_len)) {
        return PN532_NDEF_ERR_CARD_FULL;
    }

    size_t rounded_len = 0;
    if (!ndef_size_add(total_len, (size_t)block_size - 1u, &rounded_len)) {
        return PN532_NDEF_ERR_CARD_FULL;
    }

    size_t blocks_needed = rounded_len / (size_t)block_size;
    if (max_blocks > 0 && (int)blocks_needed > max_blocks) {
        return PN532_NDEF_ERR_CARD_FULL;
    }

    size_t   buf_size = blocks_needed * (size_t)block_size;
    uint8_t *buf      = calloc(buf_size, 1);
    if (buf == NULL) {
        return PN532_NDEF_ERR_NO_MEMORY;
    }

    size_t pos = 0;
    buf[pos++] = TLV_NDEF;
    if (ndef_len < 0xFF) {
        buf[pos++] = (uint8_t)ndef_len;
    } else {
        buf[pos++] = 0xFF;
        buf[pos++] = (uint8_t)((ndef_len >> 8) & 0xFF);
        buf[pos++] = (uint8_t)(ndef_len & 0xFF);
    }

    if (pn532_ndef_encode_message(msg, buf + pos, ndef_len) != ndef_len) {
        free(buf);
        return PN532_NDEF_ERR_INVALID_PARAM;
    }
    pos += ndef_len;
    buf[pos++] = TLV_TERMINATOR;

    if (blocks_needed > 1) {
        uint8_t first_block[16] = {0};

        /*
         * Hide the new TLV length until the trailing pages are programmed so a
         * concurrent reader never sees a partially updated multi-page message.
         */
        first_block[0] = TLV_NDEF;
        first_block[1] = 0x00;
        if (block_size > 2) {
            first_block[2] = TLV_TERMINATOR;
        }

        if (pn532_14443_block_write(pn532, start_block, first_block, (size_t)block_size) < 0) {
            free(buf);
            return PN532_NDEF_ERR_WRITE_FAILED;
        }
    }

    for (size_t block = 1; block < blocks_needed; block++) {
        if (pn532_14443_block_write(pn532, start_block + (int)block, buf + block * (size_t)block_size,
                                    (size_t)block_size) < 0) {
            free(buf);
            return PN532_NDEF_ERR_WRITE_FAILED;
        }
    }

    if (pn532_14443_block_write(pn532, start_block, buf, (size_t)block_size) < 0) {
        free(buf);
        return PN532_NDEF_ERR_WRITE_FAILED;
    }

    free(buf);
    return PN532_NDEF_OK;
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
#define CLASSIC_MAD2_FIRST_DATA_BLOCK  64
#define CLASSIC_MAD2_TRAILER_BLOCK     67
#define CLASSIC_MAD2_ENTRY_COUNT       23
#define CLASSIC_MAX_NDEF_SECTORS       (CLASSIC_MAD1_ENTRY_COUNT + CLASSIC_MAD2_ENTRY_COUNT)

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
        if ((pn532->tg_stale || !pn532_in_select(pn532, pn532->inListedTag)) &&
            !pn532_14443_select_by_uid(pn532, uid)) {
            return false;
        }
    }

    return pn532_14443_authenticate(pn532, key, key_type, uid, blockno);
}

static bool classic_auth_mad1(pn532_t *pn532, const pn532_uid_t *uid)
{
    static const uint8_t key_mad[6]     = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    static const uint8_t key_default[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (pn532 == NULL || uid == NULL) {
        return false;
    }

    if (!classic_try_auth_with_key(pn532, uid, CLASSIC_MAD1_FIRST_DATA_BLOCK, key_mad, PN532_MIFARE_CMD_AUTH_A)) {
        if (!classic_try_auth_with_key(pn532, uid, CLASSIC_MAD1_FIRST_DATA_BLOCK, key_default,
                                       PN532_MIFARE_CMD_AUTH_A)) {
            return false;
        }
    }

    return true;
}

static bool classic_read_mad1(pn532_t *pn532, uint8_t mad[32])
{
    if (pn532 == NULL || mad == NULL) {
        return false;
    }

    if (!pn532_14443_block_read(pn532, CLASSIC_MAD1_FIRST_DATA_BLOCK, mad, 16)) {
        return false;
    }
    if (!pn532_14443_block_read(pn532, CLASSIC_MAD1_SECOND_DATA_BLOCK, mad + 16, 16)) {
        return false;
    }

    return true;
}

static bool classic_read_mad1_gpb(pn532_t *pn532, uint8_t *gpb_out)
{
    if (pn532 == NULL || gpb_out == NULL) {
        return false;
    }

    uint8_t trailer[16];
    if (!pn532_14443_block_read(pn532, 3, trailer, sizeof(trailer))) {
        return false;
    }

    *gpb_out = trailer[9];
    return true;
}

static bool classic_read_mad2(pn532_t *pn532, const pn532_uid_t *uid, uint8_t mad[48])
{
    static const uint8_t key_mad[6]     = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    static const uint8_t key_default[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (pn532 == NULL || uid == NULL || mad == NULL) {
        return false;
    }

    if (!classic_try_auth_with_key(pn532, uid, CLASSIC_MAD2_TRAILER_BLOCK, key_mad, PN532_MIFARE_CMD_AUTH_A)) {
        if (!classic_try_auth_with_key(pn532, uid, CLASSIC_MAD2_TRAILER_BLOCK, key_default, PN532_MIFARE_CMD_AUTH_A)) {
            return false;
        }
    }

    for (int i = 0; i < 3; i++) {
        if (!pn532_14443_block_read(pn532, CLASSIC_MAD2_FIRST_DATA_BLOCK + i, mad + (size_t)i * 16u, 16)) {
            return false;
        }
    }

    return true;
}

/* CRC of a MIFARE Application Directory: CRC-8 with polynomial
 * x^8 + x^4 + x^3 + x^2 + 1 (1Dh) and preset C7h over the info byte and the
 * application identifiers. Byte 0 of the MAD holds the CRC. */
static bool classic_mad_crc_ok(const uint8_t *mad, size_t mad_len)
{
    uint8_t crc = 0xC7;
    for (size_t i = 1; i < mad_len; i++) {
        crc ^= mad[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x1D) : (uint8_t)(crc << 1);
        }
    }
    return crc == mad[0];
}

static bool classic_mad_entry_is_ndef(const uint8_t *mad, size_t mad_len, int entry, int entry_count)
{
    if (mad == NULL || entry < 0 || entry >= entry_count || mad_len < 2u + (size_t)entry_count * 2u) {
        return false;
    }

    size_t  offset = 2u + (size_t)entry * 2u;
    uint8_t aid0   = mad[offset];
    uint8_t aid1   = mad[offset + 1u];
    return (aid0 == 0x03 && aid1 == 0xE1) || (aid0 == 0xE1 && aid1 == 0x03);
}

static int classic_next_application_sector(int sector)
{
    return (sector == 15) ? 17 : (sector + 1);
}

static bool classic_collect_ndef_sectors(const uint8_t *mad, size_t mad_len, int first_sector, int entry_count,
                                         int *sectors, size_t sectors_capacity, size_t *sector_count)
{
    if (mad == NULL || sectors == NULL || sector_count == NULL || first_sector <= 0 || entry_count <= 0) {
        return false;
    }

    size_t count           = *sector_count;
    int    previous_sector = (count > 0) ? sectors[count - 1] : -1;

    for (int entry = 0; entry < entry_count; entry++) {
        if (!classic_mad_entry_is_ndef(mad, mad_len, entry, entry_count)) {
            continue;
        }

        int sector = first_sector + entry;
        if (previous_sector >= 0 && sector != classic_next_application_sector(previous_sector)) {
            return false;
        }
        if (count >= sectors_capacity) {
            return false;
        }

        sectors[count++] = sector;
        previous_sector  = sector;
    }

    *sector_count = count;
    return true;
}

static int classic_sector_first_block(int sector)
{
    if (sector < 0) {
        return -1;
    }
    if (sector < 32) {
        return sector * 4;
    }
    if (sector < 40) {
        return 128 + (sector - 32) * 16;
    }
    return -1;
}

static int classic_sector_block_count(int sector)
{
    if (sector < 0) {
        return 0;
    }
    if (sector < 32) {
        return 4;
    }
    if (sector < 40) {
        return 16;
    }
    return 0;
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

static pn532_ndef_result_t classic_read_from_selected_sectors(pn532_t *pn532, const int *sectors, size_t sector_count,
                                                              default_auth_ctx_t           *ctx,
                                                              pn532_ndef_message_parsed_t **out_msg)
{
    if (pn532 == NULL || sectors == NULL || sector_count == 0 || ctx == NULL || out_msg == NULL) {
        return PN532_NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;

    size_t   capacity = 256;
    uint8_t *buf      = malloc(capacity);
    if (buf == NULL) {
        return PN532_NDEF_ERR_NO_MEMORY;
    }

    size_t len         = 0;
    size_t tlv_pos     = 0;
    size_t ndef_offset = 0;
    size_t ndef_len    = 0;
    bool   found       = false;
    bool   read_ok     = true;
    bool   hit_end     = false;

    for (size_t sector_index = 0; sector_index < sector_count && !found && !hit_end && read_ok; sector_index++) {
        int sector      = sectors[sector_index];
        int first_block = classic_sector_first_block(sector);
        int block_count = classic_sector_block_count(sector);

        if (first_block < 0 || block_count <= 1) {
            read_ok = false;
            break;
        }
        if (!classic_auth_cb(pn532, first_block, ctx)) {
            read_ok = false;
            break;
        }

        for (int block = first_block; block < first_block + block_count - 1; block++) {
            if (len + 16 > capacity) {
                size_t new_cap = capacity * 2;
                while (new_cap < len + 16) {
                    new_cap *= 2;
                }
                uint8_t *new_buf = realloc(buf, new_cap);
                if (new_buf == NULL) {
                    free(buf);
                    return PN532_NDEF_ERR_NO_MEMORY;
                }
                buf      = new_buf;
                capacity = new_cap;
            }

            if (!pn532_14443_block_read(pn532, block, buf + len, 16)) {
                read_ok = false;
                break;
            }
            len += 16;

            if (ndef_tlv_find_ndef(buf, len, &tlv_pos, &ndef_offset, &ndef_len)) {
                if (ndef_offset + ndef_len <= len) {
                    found = true;
                    break;
                }
            } else if (tlv_pos < len && buf[tlv_pos] == TLV_TERMINATOR) {
                hit_end = true;
                break;
            }
        }
    }

    if (!found || ndef_len == 0) {
        free(buf);
        return read_ok ? PN532_NDEF_ERR_NO_NDEF : PN532_NDEF_ERR_READ_FAILED;
    }

    pn532_ndef_result_t parse_res = pn532_ndef_parse_message(buf + ndef_offset, ndef_len, out_msg);
    free(buf);
    return parse_res;
}

static int classic_mad_version_from_gpb(uint8_t gpb)
{
    if ((gpb & 0x80u) == 0) {
        return 0;
    }

    switch (gpb & 0x03u) {
    case 0x01:
        return 1;
    case 0x02:
        return 2;
    default:
        return 0;
    }
}

static pn532_ndef_result_t classic_read_ndef_from_mad(pn532_t *pn532, const pn532_uid_t *uid, default_auth_ctx_t *ctx,
                                                      pn532_ndef_message_parsed_t **out_msg)
{
    uint8_t mad1[32];
    uint8_t gpb = 0;
    int     sectors[CLASSIC_MAX_NDEF_SECTORS];
    size_t  sector_count = 0;

    if (pn532 == NULL || uid == NULL || ctx == NULL || out_msg == NULL) {
        return PN532_NDEF_ERR_INVALID_PARAM;
    }

    if (!classic_auth_mad1(pn532, uid)) {
        return PN532_NDEF_ERR_NO_NDEF;
    }
    int mad_version = 1;
    if (classic_read_mad1_gpb(pn532, &gpb)) {
        mad_version = classic_mad_version_from_gpb(gpb);
        if (mad_version == 0) {
            return PN532_NDEF_ERR_NO_NDEF;
        }
    } else {
        ESP_LOGD(TAG, "classic_read_ndef_from_mad: MAD1 GPB unreadable, assuming MAD v1");
    }
    if (!classic_read_mad1(pn532, mad1)) {
        return PN532_NDEF_ERR_NO_NDEF;
    }
    /* A directory with a wrong CRC is treated as absent. */
    if (!classic_mad_crc_ok(mad1, sizeof(mad1))) {
        ESP_LOGD(TAG, "classic_read_ndef_from_mad: MAD1 CRC mismatch");
        return PN532_NDEF_ERR_NO_NDEF;
    }

    switch (uid->subtype) {
    case PN532_MIFARE_CLASSIC_MINI:
        if (!classic_collect_ndef_sectors(mad1, sizeof(mad1), 1, 4, sectors, CLASSIC_MAX_NDEF_SECTORS, &sector_count)) {
            return PN532_NDEF_ERR_NO_NDEF;
        }
        break;
    case PN532_MIFARE_CLASSIC_1K:
        if (!classic_collect_ndef_sectors(mad1, sizeof(mad1), 1, CLASSIC_MAD1_ENTRY_COUNT, sectors,
                                          CLASSIC_MAX_NDEF_SECTORS, &sector_count)) {
            return PN532_NDEF_ERR_NO_NDEF;
        }
        break;
    case PN532_MIFARE_CLASSIC_4K:
        if (!classic_collect_ndef_sectors(mad1, sizeof(mad1), 1, CLASSIC_MAD1_ENTRY_COUNT, sectors,
                                          CLASSIC_MAX_NDEF_SECTORS, &sector_count)) {
            return PN532_NDEF_ERR_NO_NDEF;
        }
        if (mad_version == 2) {
            uint8_t mad2[48];

            if (!classic_read_mad2(pn532, uid, mad2)) {
                return PN532_NDEF_ERR_NO_NDEF;
            }
            if (!classic_mad_crc_ok(mad2, sizeof(mad2))) {
                ESP_LOGD(TAG, "classic_read_ndef_from_mad: MAD2 CRC mismatch");
                return PN532_NDEF_ERR_NO_NDEF;
            }
            if (!classic_collect_ndef_sectors(mad2, sizeof(mad2), 17, CLASSIC_MAD2_ENTRY_COUNT, sectors,
                                              CLASSIC_MAX_NDEF_SECTORS, &sector_count)) {
                return PN532_NDEF_ERR_NO_NDEF;
            }
        }
        break;
    default:
        return PN532_NDEF_ERR_UNSUPPORTED;
    }

    if (sector_count == 0) {
        return PN532_NDEF_ERR_NO_NDEF;
    }
    return classic_read_from_selected_sectors(pn532, sectors, sector_count, ctx, out_msg);
}

/* ---- Type 4 (DESFire / ISO-DEP) NDEF read ---- */

static pn532_ndef_result_t ndef_type4_select_failure_result(const pn532_t *pn532)
{
    if (pn532 == NULL || pn532->inListedTag == 0 || !pn532->session_opened) {
        return PN532_NDEF_ERR_READ_FAILED;
    }
    return PN532_NDEF_ERR_NO_NDEF;
}

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

static pn532_ndef_result_t ndef_read_type4(pn532_t *pn532, pn532_ndef_message_parsed_t **out_msg)
{
    static const uint8_t ndef_aid[]   = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    static const uint8_t cc_file_id[] = {0xE1, 0x03};

    if (!pn532_14443_4_select_file(pn532, ndef_aid, sizeof(ndef_aid))) {
        ESP_LOGD(TAG, "T4: SELECT NDEF AID failed");
        return ndef_type4_select_failure_result(pn532);
    }
    if (!pn532_14443_4_select_file(pn532, cc_file_id, sizeof(cc_file_id))) {
        ESP_LOGD(TAG, "T4: SELECT CC failed");
        return ndef_type4_select_failure_result(pn532);
    }

    uint8_t cc[15];
    size_t  cc_got = sizeof(cc);
    if (!pn532_14443_4_read_binary(pn532, 0, sizeof(cc), cc, &cc_got) || cc_got < 15) {
        ESP_LOGD(TAG, "T4: READ CC failed (%u bytes)", (unsigned)cc_got);
        return PN532_NDEF_ERR_READ_FAILED;
    }

    uint16_t mle            = ((uint16_t)cc[3] << 8) | cc[4];
    uint8_t  ndef_fid_be[2] = {cc[9], cc[10]};
    uint16_t max_ndef_size  = ((uint16_t)cc[11] << 8) | cc[12];
    /* Mapping versions 1.x to 3.x describe the NDEF file with the NDEF File
     * Control TLV (04h) read here; a higher major version may not. */
    uint8_t mapping_major = (uint8_t)(cc[2] >> 4);
    if (mapping_major < 1 || mapping_major > 3) {
        ESP_LOGD(TAG, "T4: unsupported mapping version %02X", cc[2]);
        return PN532_NDEF_ERR_UNSUPPORTED;
    }
    /* A mapping 3.x tag may carry the Extended NDEF File Control TLV (06h)
     * instead: 4-byte file size and NDEF length, for files above 32 KB. */
    if (cc[7] == 0x06) {
        ESP_LOGD(TAG, "T4: extended NDEF file is not supported");
        return PN532_NDEF_ERR_UNSUPPORTED;
    }
    if (cc[7] != 0x04 || cc[8] != 0x06 || max_ndef_size < 2) {
        ESP_LOGD(TAG, "T4: bad CC TLV (T=%02X L=%02X)", cc[7], cc[8]);
        return PN532_NDEF_ERR_PARSE_FAILED;
    }
    /* Read access 00h means free access; anything else needs a security
     * setup this driver does not do. */
    if (cc[13] != 0x00) {
        ESP_LOGD(TAG, "T4: NDEF file is read protected (access byte %02X)", cc[13]);
        return PN532_NDEF_ERR_ACCESS_DENIED;
    }
    /* Cap chunk size. MLe already counts data bytes only (SW1/SW2 are not
     * part of it), so Le = MLe is legal; two bytes of headroom are kept
     * anyway for cards that size MLe to their whole R-APDU buffer. Our READ
     * BINARY helper uses a 260-byte buffer and Le is one byte, so 248 data
     * bytes is the ceiling. */
    uint16_t chunk_max;
    if (mle <= 2 || mle > 250) {
        chunk_max = 248u;
    } else {
        chunk_max = mle - 2u;
    }

    if (!pn532_14443_4_select_file(pn532, ndef_fid_be, sizeof(ndef_fid_be))) {
        ESP_LOGD(TAG, "T4: SELECT NDEF file %02X%02X failed", ndef_fid_be[0], ndef_fid_be[1]);
        return ndef_type4_select_failure_result(pn532);
    }

    uint8_t nlen_buf[2];
    size_t  nlen_got = sizeof(nlen_buf);
    if (!pn532_14443_4_read_binary(pn532, 0, 2, nlen_buf, &nlen_got) || nlen_got < 2) {
        return PN532_NDEF_ERR_READ_FAILED;
    }
    uint16_t nlen = ((uint16_t)nlen_buf[0] << 8) | nlen_buf[1];
    if (nlen == 0) {
        return PN532_NDEF_ERR_NO_NDEF;
    }
    if ((uint32_t)nlen + 2u > max_ndef_size) {
        /* The length does not fit the file the capability container
         * describes: the tag is inconsistent. */
        return PN532_NDEF_ERR_PARSE_FAILED;
    }

    uint8_t *raw = malloc(nlen);
    if (raw == NULL) {
        return PN532_NDEF_ERR_NO_MEMORY;
    }
    uint16_t read_off  = 2;
    uint16_t remaining = nlen;
    while (remaining > 0) {
        uint8_t want = (remaining > chunk_max) ? (uint8_t)chunk_max : (uint8_t)remaining;
        size_t  got  = want;
        if (!pn532_14443_4_read_binary(pn532, read_off, want, raw + (read_off - 2), &got) || got != want) {
            free(raw);
            return PN532_NDEF_ERR_READ_FAILED;
        }
        read_off += want;
        remaining -= want;
    }

    pn532_ndef_result_t parse_result = pn532_ndef_parse_message(raw, nlen, out_msg);
    free(raw);
    return parse_result;
}

pn532_ndef_result_t pn532_ndef_read_card_auto(pn532_t *pn532, pn532_uid_t *uid, pn532_ndef_message_parsed_t **out_msg)
{
    if (pn532 == NULL || uid == NULL || out_msg == NULL) {
        return PN532_NDEF_ERR_INVALID_PARAM;
    }
    *out_msg = NULL;

    switch (uid->subtype) {
    case PN532_MIFARE_ULTRALIGHT:
    case PN532_MIFARE_ULTRALIGHT_C:
    case PN532_MIFARE_ULTRALIGHT_EV1:
    case PN532_MIFARE_NTAG210:
    case PN532_MIFARE_NTAG212:
    case PN532_MIFARE_NTAG213:
    case PN532_MIFARE_NTAG215:
    case PN532_MIFARE_NTAG216: {
        bool has_cc = false;
        if (!pn532_type2_prepare_layout(pn532, uid, &has_cc)) {
            return PN532_NDEF_ERR_READ_FAILED;
        }
        /* Capability container at page 3, NDEF data from page 4. A tag
         * without the container, or with an empty data area, is not NDEF
         * formatted. */
        if (!has_cc || uid->blocks_count <= 4) {
            return PN532_NDEF_ERR_NO_NDEF;
        }
        pn532_ndef_result_t res = type2_read_ndef(pn532, 4, uid->blocks_count - 4, out_msg);
        if (res == PN532_NDEF_ERR_READ_FAILED) {
            if (!pn532_14443_select_by_uid(pn532, uid)) {
                return res;
            }
            if (!pn532_type2_prepare_layout(pn532, uid, &has_cc)) {
                return res;
            }
            if (!has_cc || uid->blocks_count <= 4) {
                return PN532_NDEF_ERR_NO_NDEF;
            }
            res = type2_read_ndef(pn532, 4, uid->blocks_count - 4, out_msg);
        }
        return res;
    }

    case PN532_MIFARE_CLASSIC_1K:
    case PN532_MIFARE_CLASSIC_4K:
    case PN532_MIFARE_CLASSIC_MINI: {
        if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, uid)) {
            return PN532_NDEF_ERR_READ_FAILED;
        }
        static const uint8_t key_a_default[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t key_a_ndef[6]    = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
        default_auth_ctx_t   ctx              = {
                           .uid = uid, .primary_key = key_a_ndef, .secondary_key = key_a_default, .key_type = PN532_MIFARE_CMD_AUTH_A};
        return classic_read_ndef_from_mad(pn532, uid, &ctx, out_msg);
    }

    case PN532_MIFARE_DESFIRE: {
        if (pn532->inListedTag == 0 && !pn532_14443_select_by_uid(pn532, uid)) {
            return PN532_NDEF_ERR_READ_FAILED;
        }
        pn532_ndef_result_t res = ndef_read_type4(pn532, out_msg);
        if (res == PN532_NDEF_ERR_READ_FAILED) {
            pn532_delay_ms(10);
            if (pn532->inListedTag == 0) {
                if (!pn532_14443_select_by_uid(pn532, uid)) {
                    return res;
                }
            }
            res = ndef_read_type4(pn532, out_msg);
        }
        return res;
    }

    default:
        return PN532_NDEF_ERR_UNSUPPORTED;
    }
}

void pn532_ndef_free_parsed_message(pn532_ndef_message_parsed_t *msg)
{
    free(msg);
}

/* ---- Record helpers ---- */

bool pn532_ndef_extract_text(const pn532_ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out,
                             char *lang_buf, bool *is_utf16)
{
    if (rec == NULL || text_out == NULL || text_len_out == NULL) {
        return false;
    }
    if (rec->tnf != PN532_NDEF_TNF_WELL_KNOWN || rec->type_len != 1 || rec->type == NULL || rec->type[0] != 'T') {
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

size_t pn532_ndef_extract_uri(const pn532_ndef_record_t *rec, char *uri_buf, size_t uri_buf_len)
{
    if (rec == NULL) {
        return 0;
    }
    if (rec->tnf != PN532_NDEF_TNF_WELL_KNOWN || rec->type_len != 1 || rec->type == NULL || rec->type[0] != 'U') {
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

pn532_ndef_record_type_t pn532_ndef_get_record_type(const pn532_ndef_record_t *rec)
{
    if (rec == NULL) {
        return PN532_NDEF_RECORD_TYPE_UNKNOWN;
    }
    if (rec->tnf == PN532_NDEF_TNF_EMPTY) {
        return PN532_NDEF_RECORD_TYPE_EMPTY;
    }
    if (rec->tnf == PN532_NDEF_TNF_MEDIA_TYPE) {
        return PN532_NDEF_RECORD_TYPE_MIME;
    }
    if (rec->tnf == PN532_NDEF_TNF_EXTERNAL) {
        return PN532_NDEF_RECORD_TYPE_EXTERNAL;
    }
    if (rec->tnf == PN532_NDEF_TNF_WELL_KNOWN && rec->type != NULL && rec->type_len > 0) {
        if (rec->type_len == 1 && rec->type[0] == 'T') {
            return PN532_NDEF_RECORD_TYPE_TEXT;
        }
        if (rec->type_len == 1 && rec->type[0] == 'U') {
            return PN532_NDEF_RECORD_TYPE_URI;
        }
        if (rec->type_len == 2 && rec->type[0] == 'S' && rec->type[1] == 'p') {
            return PN532_NDEF_RECORD_TYPE_SMARTPOSTER;
        }
    }
    return PN532_NDEF_RECORD_TYPE_UNKNOWN;
}

bool pn532_ndef_record_is_text(const pn532_ndef_record_t *rec)
{
    return pn532_ndef_get_record_type(rec) == PN532_NDEF_RECORD_TYPE_TEXT;
}
bool pn532_ndef_record_is_uri(const pn532_ndef_record_t *rec)
{
    return pn532_ndef_get_record_type(rec) == PN532_NDEF_RECORD_TYPE_URI;
}
bool pn532_ndef_record_is_smartposter(const pn532_ndef_record_t *rec)
{
    return pn532_ndef_get_record_type(rec) == PN532_NDEF_RECORD_TYPE_SMARTPOSTER;
}

size_t pn532_ndef_decode_smartposter(const pn532_ndef_record_t *rec, pn532_ndef_record_t *records, size_t capacity)
{
    if (!pn532_ndef_record_is_smartposter(rec) || rec->payload == NULL || rec->payload_len == 0) {
        return 0;
    }
    return ndef_decode_message(rec->payload, rec->payload_len, records, capacity);
}

const char *pn532_ndef_result_to_string(pn532_ndef_result_t result)
{
    switch (result) {
    case PN532_NDEF_OK:
        return "OK";
    case PN532_NDEF_ERR_INVALID_PARAM:
        return "Invalid parameter";
    case PN532_NDEF_ERR_NO_MEMORY:
        return "Out of memory";
    case PN532_NDEF_ERR_READ_FAILED:
        return "Card read failed";
    case PN532_NDEF_ERR_WRITE_FAILED:
        return "Card write failed";
    case PN532_NDEF_ERR_NO_NDEF:
        return "No NDEF data found";
    case PN532_NDEF_ERR_PARSE_FAILED:
        return "NDEF parse failed";
    case PN532_NDEF_ERR_BUFFER_TOO_SMALL:
        return "Buffer too small";
    case PN532_NDEF_ERR_CARD_FULL:
        return "Card capacity exceeded";
    case PN532_NDEF_ERR_UNSUPPORTED:
        return "Unsupported card";
    case PN532_NDEF_ERR_ACCESS_DENIED:
        return "NDEF data is read protected";
    default:
        return "Unknown";
    }
}
