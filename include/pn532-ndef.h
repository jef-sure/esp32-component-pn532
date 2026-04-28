/**
 * @file pn532-ndef.h
 * @brief Public NDEF parsing, encoding, and helper APIs built on top of pn532.h.
 * @copyright Copyright (c) 2026 Anton Petrusevich.
 *
 * Mirrors the surface of the jef-sure pn5180 NDEF module but talks to a PN532
 * instead. The main entry point is pn532_ndef_read_card_auto(), which selects
 * the card if needed, applies the card-type specific read policy, and returns a
 * parsed zero-copy view of the NDEF message.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pn532.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief NDEF Type Name Format (TNF) values */
typedef enum
{
    NDEF_TNF_EMPTY        = 0x00,
    NDEF_TNF_WELL_KNOWN   = 0x01,
    NDEF_TNF_MEDIA_TYPE   = 0x02,
    NDEF_TNF_ABSOLUTE_URI = 0x03,
    NDEF_TNF_EXTERNAL     = 0x04,
    NDEF_TNF_UNKNOWN      = 0x05,
    NDEF_TNF_UNCHANGED    = 0x06,
    NDEF_TNF_RESERVED     = 0x07,
} ndef_tnf_t;

/** @brief NDEF operation result codes used by the public helpers below. */
typedef enum
{
    NDEF_OK                   = 0,
    NDEF_ERR_INVALID_PARAM    = -1,
    NDEF_ERR_NO_MEMORY        = -2,
    NDEF_ERR_READ_FAILED      = -3,
    NDEF_ERR_WRITE_FAILED     = -4,
    NDEF_ERR_NO_NDEF          = -5,
    NDEF_ERR_PARSE_FAILED     = -6,
    NDEF_ERR_BUFFER_TOO_SMALL = -7,
    NDEF_ERR_CARD_FULL        = -8,
    NDEF_ERR_UNSUPPORTED      = -9,
} ndef_result_t;

/** @brief NDEF record descriptor referencing bytes owned by ndef_message_parsed_t::raw_data. */
typedef struct
{
    ndef_tnf_t     tnf;
    uint8_t        type_len;
    uint8_t        id_len;
    uint32_t       payload_len;
    const uint8_t *type;
    const uint8_t *id;
    const uint8_t *payload;
} ndef_record_t;

/** @brief Mutable NDEF message builder used by the encoder and write helpers. */
typedef struct
{
    ndef_record_t *records;
    size_t         record_count;
    size_t         capacity;
} ndef_message_t;

/** @name Common Well-known RTD type values
 * @{ */
extern const uint8_t NDEF_RTD_TEXT[];
extern const uint8_t NDEF_RTD_URI[];
extern const uint8_t NDEF_RTD_SMARTPOSTER[];

#define NDEF_RTD_TEXT_LEN        1
#define NDEF_RTD_URI_LEN         1
#define NDEF_RTD_SMARTPOSTER_LEN 2
/** @} */

/**
 * @brief Parsed NDEF message returned by pn532_ndef_read_card_auto().
 *
 * The structure, its records array, and raw_data buffer are allocated together
 * in one heap block. Release them with ndef_free_parsed_message().
 */
typedef struct
{
    uint8_t       *raw_data;
    size_t         raw_data_len;
    ndef_record_t *records;
    size_t         record_count;
} ndef_message_parsed_t;

/** @brief Common high-level record classes recognised by the helper predicates. */
typedef enum
{
    NDEF_RECORD_TYPE_UNKNOWN     = 0,
    NDEF_RECORD_TYPE_TEXT        = 1,
    NDEF_RECORD_TYPE_URI         = 2,
    NDEF_RECORD_TYPE_SMARTPOSTER = 3,
    NDEF_RECORD_TYPE_MIME        = 4,
    NDEF_RECORD_TYPE_EXTERNAL    = 5,
    NDEF_RECORD_TYPE_EMPTY       = 6,
} ndef_record_type_t;

/** @brief Initialise an NDEF message builder with caller-owned record storage. */
void ndef_message_init(ndef_message_t *msg, ndef_record_t *records, size_t capacity);

/** @brief Append a record to an NDEF message builder with a shallow copy. */
bool ndef_message_add(ndef_message_t *msg, const ndef_record_t *rec);

/** @brief Fill an NDEF record descriptor from caller-owned type/id/payload storage. */
void ndef_record_init(ndef_record_t *rec, ndef_tnf_t tnf, const uint8_t *type, uint8_t type_len, const uint8_t *id,
                      uint8_t id_len, const uint8_t *payload, uint32_t payload_len);

/**
 * @brief Encode an NDEF message into binary format.
 *
 * If out is NULL or out_len is 0, returns the required output size.
 */
size_t ndef_encode_message(const ndef_message_t *msg, uint8_t *out, size_t out_len);

/** @brief Build a Well-known Text record whose payload is stored in payload_buf. */
bool ndef_make_text_record(ndef_record_t *rec, const char *lang_code, const uint8_t *text, size_t text_len,
                           bool utf16, uint8_t *payload_buf, size_t payload_buf_len);

/** @brief Build a Well-known URI record whose payload is stored in payload_buf. */
bool ndef_make_uri_record(ndef_record_t *rec, const char *uri, bool abbreviate, uint8_t *payload_buf,
                          size_t payload_buf_len);

/** @brief Build a MIME record with caller-owned type buffer and payload storage. */
bool ndef_make_mime_record(ndef_record_t *rec, const char *mime_type, const uint8_t *data, size_t data_len,
                           uint8_t *type_buf, size_t type_buf_len);

/** @brief Build an external-type record with caller-owned type buffer and payload storage. */
bool ndef_make_external_record(ndef_record_t *rec, const char *type_name, const uint8_t *data, size_t data_len,
                               uint8_t *type_buf, size_t type_buf_len);

/**
 * @brief Encode and write an NDEF TLV to the currently selected block-addressed tag.
 *
 * This helper writes a TLV-wrapped NDEF message starting at start_block. It is
 * intended for already selected Type 2 / NTAG style memory-mapped tags.
 * MIFARE Classic is intentionally not supported here because a correct writer
 * must authenticate sector-by-sector and skip sector trailers / MAD updates.
 */
ndef_result_t ndef_write_to_selected_card(pn532_t *pn532, const ndef_message_t *msg, int start_block, int block_size,
                                          int max_blocks);

/**
 * @brief One-shot helper that selects @p uid, picks the right layout, runs default-key
 *        auth on Mifare Classic, and reads the NDEF message.
 *
 * For Type 2 tags the helper reads the capability container to refine subtype
 * and capacity. For MIFARE Classic Mini / 1K it uses MAD1 to locate NDEF
 * sectors, and for 4K it also reads MAD2 when advertised, so non-NDEF cards
 * return NDEF_ERR_NO_NDEF quickly instead of falling back to a flat scan.
 *
 * @param pn532 Active PN532 device.
 * @param uid Target returned by pn532_14443_get_all_uids().
 * @param out_msg Receives a heap-allocated parsed message on success.
 * @return NDEF_OK on success, NDEF_ERR_NO_NDEF when no NDEF mapping/message is present,
 *         NDEF_ERR_UNSUPPORTED for unsupported card types, or another negative error.
 */
ndef_result_t pn532_ndef_read_card_auto(pn532_t *pn532, pn532_uid_t *uid, ndef_message_parsed_t **out_msg);

/** @brief Free a parsed message returned by pn532_ndef_read_card_auto(). */
void ndef_free_parsed_message(ndef_message_parsed_t *msg);

/**
 * @brief Extract the payload metadata of a Well-known Text ("T") record.
 *
 * The returned text pointer aliases rec->payload. lang_buf and is_utf16 are
 * optional outputs. When lang_buf is provided, it must have room for the full
 * language code plus a trailing NUL byte; 64 bytes is sufficient for all valid
 * NDEF Text records.
 */
bool ndef_extract_text(const ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out, char *lang_buf,
                       bool *is_utf16);

/**
 * @brief Expand a Well-known URI ("U") record into a full URI string.
 * @return total expanded URI length (may exceed @p uri_buf_len; truncates if so), 0 on error.
 */
size_t ndef_extract_uri(const ndef_record_t *rec, char *uri_buf, size_t uri_buf_len);

/** @brief Classify a record into a small set of common NDEF record categories. */
ndef_record_type_t ndef_get_record_type(const ndef_record_t *rec);

/** @brief Return true when rec is a Well-known Text record. */
bool               ndef_record_is_text(const ndef_record_t *rec);

/** @brief Return true when rec is a Well-known URI record. */
bool               ndef_record_is_uri(const ndef_record_t *rec);

/** @brief Return true when rec is a Well-known Smart Poster record. */
bool               ndef_record_is_smartposter(const ndef_record_t *rec);

/**
 * @brief Decode nested records stored inside a Smart Poster payload.
 *
 * @param rec Smart Poster record.
 * @param records Output array supplied by the caller.
 * @param capacity Number of elements available in records.
 * @return Number of nested records decoded, or 0 on parse failure.
 */
size_t ndef_decode_smartposter(const ndef_record_t *rec, ndef_record_t *records, size_t capacity);

/** @brief Convert an ndef_result_t to a static string literal. */
const char *ndef_result_to_string(ndef_result_t result);

#ifdef __cplusplus
}
#endif
