/**
 * @file pn532-mifare.h
 * @brief Low-level MIFARE Classic / Ultralight helpers layered on the PN532 exchange API.
 * @copyright Copyright (c) 2026 Anton Petrusevich.
 */

#pragma once

#include "pn532.h"

/** @brief MIFARE Classic authenticate with Key A. */
#define MIFARE_CMD_AUTH_A           (0x60)
/** @brief MIFARE Classic authenticate with Key B. */
#define MIFARE_CMD_AUTH_B           (0x61)
/** @brief MIFARE Classic / Ultralight READ command. */
#define MIFARE_CMD_READ             (0x30)
/** @brief MIFARE Classic 16-byte WRITE command. */
#define MIFARE_CMD_WRITE            (0xA0)
/** @brief MIFARE Classic TRANSFER value command. */
#define MIFARE_CMD_TRANSFER         (0xB0)
/** @brief MIFARE Classic DECREMENT value command. */
#define MIFARE_CMD_DECREMENT        (0xC0)
/** @brief MIFARE Classic INCREMENT value command. */
#define MIFARE_CMD_INCREMENT        (0xC1)
/** @brief MIFARE Classic RESTORE value command. */
#define MIFARE_CMD_RESTORE          (0xC2)
/** @brief Backward-compatible alias for the RESTORE value command. */
#define MIFARE_CMD_STORE            MIFARE_CMD_RESTORE
/** @brief Ultralight 4-byte page WRITE command. */
#define MIFARE_ULTRALIGHT_CMD_WRITE (0xA2)

/**
 * @brief Send a raw MIFARE Classic authenticate command.
 *
 * Most applications should prefer pn532_14443_authenticate(), which derives the
 * correct 4-byte UID slice from pn532_uid_t. This low-level helper expects the
 * 4 UID bytes required by the on-card auth primitive.
 *
 * @return 0 on success, -1 on invalid arguments, -2 on exchange/auth failure.
 */
int16_t pn532_mifare_authenticate(pn532_t *pn532, uint8_t blockno, const uint8_t *key, uint8_t key_type,
                                  const uint8_t uid[4]);

/**
 * @brief Read a MIFARE Classic block or an Ultralight/NTAG READ window.
 *
 * Most callers that already operate on a selected ISO14443A target should
 * prefer pn532_14443_block_read().
 *
 * For Classic, blockno addresses one 16-byte block. For Type 2 tags, READ from
 * one page returns 16 bytes covering four consecutive pages, so callers should
 * typically provide a 16-byte buffer there as well.
 */
bool pn532_mifare_block_read(pn532_t *pn532, int blockno, uint8_t *buffer, size_t buffer_len);

/**
 * @brief Write one MIFARE Classic block or one Ultralight page.
 *
 * Most callers that already operate on a selected ISO14443A target should
 * prefer pn532_14443_block_write().
 *
 * buffer_len >= 16 issues the Classic 16-byte WRITE command. buffer_len >= 4
 * issues the Ultralight 4-byte page write.
 *
 * @return 0 on success, -1 on invalid arguments, -2 on exchange failure.
 */
int pn532_mifare_block_write(pn532_t *pn532, int blockno, const uint8_t *buffer, size_t buffer_len);

/** @brief Read and validate a MIFARE Classic value block. */
bool pn532_mifare_value_read(pn532_t *pn532, uint8_t blockno, int32_t *value);

/** @brief Encode and write a MIFARE Classic value block. */
bool pn532_mifare_value_write(pn532_t *pn532, uint8_t blockno, int32_t value, uint8_t addr);

/** @brief Stage a MIFARE Classic INCREMENT operation in the transfer buffer. */
bool pn532_mifare_increment(pn532_t *pn532, uint8_t blockno, uint32_t delta);

/** @brief Stage a MIFARE Classic DECREMENT operation in the transfer buffer. */
bool pn532_mifare_decrement(pn532_t *pn532, uint8_t blockno, uint32_t delta);

/** @brief Stage a MIFARE Classic RESTORE operation in the transfer buffer. */
bool pn532_mifare_restore(pn532_t *pn532, uint8_t blockno);

/** @brief Commit the current transfer buffer to a MIFARE Classic value block. */
bool pn532_mifare_transfer(pn532_t *pn532, uint8_t blockno);