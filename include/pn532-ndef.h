/**
 * @file pn532-ndef.h
 * @brief Public NDEF parsing, encoding, and helper APIs built on top of pn532.h.
 * @copyright Copyright (c) 2026 Anton Petrusevich.
 *
 * Mirrors the surface of the jef-sure pn5180 NDEF module but talks to a PN532
 * instead. The main entry point is pn532_ndef_read_card_auto(), which selects
 * the card if needed, applies the card-type specific read policy, and returns a
 * parsed NDEF message that owns its storage.
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
    PN532_NDEF_TNF_EMPTY        = 0x00,
    PN532_NDEF_TNF_WELL_KNOWN   = 0x01,
    PN532_NDEF_TNF_MEDIA_TYPE   = 0x02,
    PN532_NDEF_TNF_ABSOLUTE_URI = 0x03,
    PN532_NDEF_TNF_EXTERNAL     = 0x04,
    PN532_NDEF_TNF_UNKNOWN      = 0x05,
    PN532_NDEF_TNF_UNCHANGED    = 0x06,
    PN532_NDEF_TNF_RESERVED     = 0x07,
} pn532_ndef_tnf_t;

/** @brief NDEF operation result codes used by the public helpers below. */
typedef enum
{
    PN532_NDEF_OK                   = 0,
    PN532_NDEF_ERR_INVALID_PARAM    = -1,
    PN532_NDEF_ERR_NO_MEMORY        = -2,
    PN532_NDEF_ERR_READ_FAILED      = -3,
    PN532_NDEF_ERR_WRITE_FAILED     = -4,
    PN532_NDEF_ERR_NO_NDEF          = -5,
    PN532_NDEF_ERR_PARSE_FAILED     = -6,
    PN532_NDEF_ERR_BUFFER_TOO_SMALL = -7, /**< Reserved: not returned by the current API. */
    PN532_NDEF_ERR_CARD_FULL        = -8,
    PN532_NDEF_ERR_UNSUPPORTED      = -9,
    PN532_NDEF_ERR_ACCESS_DENIED    = -10, /**< The NDEF data is read protected. */
} pn532_ndef_result_t;

/** @brief NDEF record descriptor referencing storage owned by pn532_ndef_message_parsed_t. */
typedef struct
{
    pn532_ndef_tnf_t tnf;
    uint8_t          type_len;
    uint8_t          id_len;
    uint32_t         payload_len;
    const uint8_t   *type;
    const uint8_t   *id;
    const uint8_t   *payload;
} pn532_ndef_record_t;

/** @brief Mutable NDEF message builder used by the encoder and write helpers. */
typedef struct
{
    pn532_ndef_record_t *records;
    size_t               record_count;
    size_t               capacity;
} pn532_ndef_message_t;

/** @name Common Well-known RTD type values
 * @{ */
extern const uint8_t PN532_NDEF_RTD_TEXT[];
extern const uint8_t PN532_NDEF_RTD_URI[];
extern const uint8_t PN532_NDEF_RTD_SMARTPOSTER[];

#define PN532_NDEF_RTD_TEXT_LEN        1
#define PN532_NDEF_RTD_URI_LEN         1
#define PN532_NDEF_RTD_SMARTPOSTER_LEN 2
/** @} */

/**
 * @brief Parsed NDEF message returned by pn532_ndef_read_card_auto().
 *
 * The structure, its records array, and raw_data buffer are allocated together
 * in one heap block. Release them with pn532_ndef_free_parsed_message().
 */
typedef struct
{
    uint8_t             *raw_data;
    size_t               raw_data_len;
    pn532_ndef_record_t *records;
    size_t               record_count;
} pn532_ndef_message_parsed_t;

/**
 * @brief Parse an encoded NDEF message into logical records.
 *
 * Physical records carrying the CF flag are validated and reassembled. The
 * first chunk supplies TNF, type, and ID; continuation chunks must use
 * PN532_NDEF_TNF_UNCHANGED and their payloads are concatenated into one logical
 * record. The returned message owns both the original encoded bytes and any
 * assembled payload storage.
 *
 * @param raw_data Encoded NDEF message bytes (without a TLV or NLEN prefix).
 * @param raw_data_len Number of encoded bytes.
 * @param out_msg Receives an allocation released by pn532_ndef_free_parsed_message();
 *                set to NULL on any error.
 * @return PN532_NDEF_OK or an NDEF error code.
 */
pn532_ndef_result_t pn532_ndef_parse_message(const uint8_t *raw_data, size_t raw_data_len,
                                             pn532_ndef_message_parsed_t **out_msg);

/** @brief Common high-level record classes recognised by the helper predicates. */
typedef enum
{
    PN532_NDEF_RECORD_TYPE_UNKNOWN     = 0,
    PN532_NDEF_RECORD_TYPE_TEXT        = 1,
    PN532_NDEF_RECORD_TYPE_URI         = 2,
    PN532_NDEF_RECORD_TYPE_SMARTPOSTER = 3,
    PN532_NDEF_RECORD_TYPE_MIME        = 4,
    PN532_NDEF_RECORD_TYPE_EXTERNAL    = 5,
    PN532_NDEF_RECORD_TYPE_EMPTY       = 6,
} pn532_ndef_record_type_t;

/** @brief Initialise an NDEF message builder with caller-owned record storage. */
void pn532_ndef_message_init(pn532_ndef_message_t *msg, pn532_ndef_record_t *records, size_t capacity);

/** @brief Append a record to an NDEF message builder with a shallow copy. */
bool pn532_ndef_message_add(pn532_ndef_message_t *msg, const pn532_ndef_record_t *rec);

/** @brief Fill an NDEF record descriptor from caller-owned type/id/payload storage. */
void pn532_ndef_record_init(pn532_ndef_record_t *rec, pn532_ndef_tnf_t tnf, const uint8_t *type, uint8_t type_len,
                            const uint8_t *id, uint8_t id_len, const uint8_t *payload, uint32_t payload_len);

/**
 * @brief Encode an NDEF message into binary format.
 *
 * If out is NULL or out_len is 0, returns the required output size.
 *
 * A record the parser of this driver would refuse is not encoded: an Empty
 * record (PN532_NDEF_TNF_EMPTY) with a type, ID or payload, an Unknown record
 * (PN532_NDEF_TNF_UNKNOWN) with a type, and the TNF values
 * PN532_NDEF_TNF_UNCHANGED and PN532_NDEF_TNF_RESERVED.
 *
 * @return Number of bytes written; 0 when out_len is smaller than the encoded
 *         message, when a record has a length without a buffer or is one of
 *         the records above, or when msg is NULL. An empty message also
 *         encodes to 0 bytes.
 */
size_t pn532_ndef_encode_message(const pn532_ndef_message_t *msg, uint8_t *out, size_t out_len);

/** @brief Build a Well-known Text record whose payload is stored in payload_buf. */
bool pn532_ndef_make_text_record(pn532_ndef_record_t *rec, const char *lang_code, const uint8_t *text, size_t text_len,
                                 bool utf16, uint8_t *payload_buf, size_t payload_buf_len);

/** @brief Build a Well-known URI record whose payload is stored in payload_buf. */
bool pn532_ndef_make_uri_record(pn532_ndef_record_t *rec, const char *uri, bool abbreviate, uint8_t *payload_buf,
                                size_t payload_buf_len);

/** @brief Build a MIME record with caller-owned type buffer and payload storage. */
bool pn532_ndef_make_mime_record(pn532_ndef_record_t *rec, const char *mime_type, const uint8_t *data, size_t data_len,
                                 uint8_t *type_buf, size_t type_buf_len);

/** @brief Build an external-type record with caller-owned type buffer and payload storage. */
bool pn532_ndef_make_external_record(pn532_ndef_record_t *rec, const char *type_name, const uint8_t *data,
                                     size_t data_len, uint8_t *type_buf, size_t type_buf_len);

/**
 * @brief Encode and write an NDEF TLV to the currently selected block-addressed tag.
 *
 * This helper writes a TLV-wrapped NDEF message starting at start_block. It is
 * intended for already selected Type 2 / NTAG style memory-mapped tags.
 * MIFARE Classic is intentionally not supported here because a correct writer
 * must authenticate sector-by-sector and skip sector trailers / MAD updates.
 *
 * The tag must be NDEF formatted. The helper reads the capability container
 * (page 3) and keeps the write inside the data area it describes
 * (pages 4 .. 3 + CC[2] * 2), so the lock and configuration pages behind it
 * are never written, whatever max_blocks says.
 *
 * @param start_block First page to write; 4 for a tag whose data area holds
 *                    only the NDEF message. Pages 0..3 (UID, lock bytes,
 *                    capability container) are refused.
 * @param block_size Page size in bytes; only 4 is supported.
 * @param max_blocks Number of pages the message may take, counted from
 *                   start_block (not a page number and not the size of the
 *                   tag). Must be positive.
 * @return PN532_NDEF_OK on success;
 *         PN532_NDEF_ERR_INVALID_PARAM for start_block below 4, a non-positive
 *         max_blocks, or a message that cannot be encoded;
 *         PN532_NDEF_ERR_UNSUPPORTED for a block_size other than 4;
 *         PN532_NDEF_ERR_CARD_FULL when the message needs more than max_blocks
 *         pages, does not fit the data area, or is longer than 65534 bytes;
 *         PN532_NDEF_ERR_READ_FAILED when the capability container cannot be
 *         read; PN532_NDEF_ERR_NO_NDEF when the tag has none;
 *         PN532_NDEF_ERR_WRITE_FAILED when a page write fails.
 */
pn532_ndef_result_t pn532_ndef_write_to_selected_card(pn532_t *pn532, const pn532_ndef_message_t *msg, int start_block,
                                                      int block_size, int max_blocks);

/**
 * @brief One-shot helper that selects @p uid, picks the right layout, runs default-key
 *        auth on Mifare Classic, and reads the NDEF message.
 *
 * For Type 2 tags the helper reads the capability container to refine subtype
 * and capacity; a tag without the capability container magic (E1h) or with
 * an empty data area returns PN532_NDEF_ERR_NO_NDEF without scanning the memory.
 * For MIFARE Classic Mini / 1K it uses MAD1 to locate NDEF sectors, and for
 * 4K it also reads MAD2 when advertised, so non-NDEF cards return
 * PN532_NDEF_ERR_NO_NDEF quickly instead of falling back to a flat scan. A
 * directory with a wrong CRC is treated as absent. For Type 4 tags a
 * read-protected NDEF file is PN532_NDEF_ERR_ACCESS_DENIED; an unknown
 * mapping version or an extended NDEF file (Extended NDEF File Control TLV,
 * files above 32 KB) is PN532_NDEF_ERR_UNSUPPORTED.
 *
 * @param pn532 Active PN532 device.
 * @param uid Target returned by pn532_14443_get_all_uids().
 * @param out_msg Receives a heap-allocated parsed message on success.
 * @return PN532_NDEF_OK on success, PN532_NDEF_ERR_NO_NDEF when no NDEF mapping/message is present,
 *         PN532_NDEF_ERR_UNSUPPORTED for unsupported card types, or another negative error.
 */
pn532_ndef_result_t pn532_ndef_read_card_auto(pn532_t *pn532, pn532_uid_t *uid, pn532_ndef_message_parsed_t **out_msg);

/** @brief Free a parsed message returned by pn532_ndef_read_card_auto(). */
void pn532_ndef_free_parsed_message(pn532_ndef_message_parsed_t *msg);

/**
 * @brief Extract the payload metadata of a Well-known Text ("T") record.
 *
 * The returned text pointer aliases rec->payload. lang_buf and is_utf16 are
 * optional outputs. When lang_buf is provided, it must have room for the full
 * language code plus a trailing NUL byte; 64 bytes is sufficient for all valid
 * NDEF Text records.
 */
bool pn532_ndef_extract_text(const pn532_ndef_record_t *rec, const uint8_t **text_out, size_t *text_len_out,
                             char *lang_buf, bool *is_utf16);

/**
 * @brief Expand a Well-known URI ("U") record into a full URI string.
 *
 * uri_buf always receives a NUL-terminated string when uri_buf_len > 0; pass
 * NULL to query the length only.
 *
 * @return total expanded URI length without the terminating NUL (it may
 *         exceed uri_buf_len - 1, in which case the string is truncated),
 *         0 on error.
 */
size_t pn532_ndef_extract_uri(const pn532_ndef_record_t *rec, char *uri_buf, size_t uri_buf_len);

/** @brief Classify a record into a small set of common NDEF record categories. */
pn532_ndef_record_type_t pn532_ndef_get_record_type(const pn532_ndef_record_t *rec);

/** @brief Return true when rec is a Well-known Text record. */
bool pn532_ndef_record_is_text(const pn532_ndef_record_t *rec);

/** @brief Return true when rec is a Well-known URI record. */
bool pn532_ndef_record_is_uri(const pn532_ndef_record_t *rec);

/** @brief Return true when rec is a Well-known Smart Poster record. */
bool pn532_ndef_record_is_smartposter(const pn532_ndef_record_t *rec);

/**
 * @brief Decode nested records stored inside a Smart Poster payload.
 *
 * @param rec Smart Poster record.
 * @param records Output array supplied by the caller.
 * @param capacity Number of elements available in records.
 * The payload must be a well-formed NDEF message (MB on the first record, ME
 * on the last, nothing after it). The records point into rec->payload, so a
 * Smart Poster with chunked nested records is not supported.
 *
 * @return Number of nested records decoded (at most capacity), or 0 when the
 *         payload is malformed or chunked.
 */
size_t pn532_ndef_decode_smartposter(const pn532_ndef_record_t *rec, pn532_ndef_record_t *records, size_t capacity);

/** @brief Convert an pn532_ndef_result_t to a static string literal. */
const char *pn532_ndef_result_to_string(pn532_ndef_result_t result);

#ifdef __cplusplus
}
#endif
