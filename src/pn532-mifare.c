#include "pn532-internal.h"
#include "pn532-mifare.h"

#include <string.h>

#include "esp_log.h"

static const char *TAG = "PN532-MIFARE";

#define PN532_MIFARE_AUTH_TIMEOUT_MS 1500

int16_t pn532_mifare_authenticate(pn532_t *pn532, uint8_t blockno, const uint8_t *key, uint8_t key_type, const uint8_t uid[4])
{
    if (key == NULL || uid == NULL) {
        return -1;
    }

    uint8_t data[] = {
        key_type,
        blockno,
        key[0], key[1], key[2], key[3], key[4], key[5],
        uid[0], uid[1], uid[2], uid[3],
    };
    size_t response_len = 0;
    return pn532_in_data_exchange(pn532, data, sizeof(data), NULL, &response_len, PN532_MIFARE_AUTH_TIMEOUT_MS) ? 0 : -2;
}

bool pn532_mifare_block_read(pn532_t *pn532, int blockno, uint8_t *buffer, size_t buffer_len)
{
    if (buffer == NULL || buffer_len == 0) {
        return false;
    }

    uint8_t cmd[] = {MIFARE_CMD_READ, (uint8_t)blockno};
    size_t response_len = buffer_len;
    if (!pn532_in_data_exchange(pn532, cmd, sizeof(cmd), buffer, &response_len, (uint16_t)pn532->timeout_ms)) {
        return false;
    }
    return response_len == 16 || response_len == 4;
}

int pn532_mifare_block_write(pn532_t *pn532, int blockno, const uint8_t *buffer, size_t buffer_len)
{
    if (buffer == NULL) {
        return -1;
    }

    uint8_t cmd[18];
    size_t cmd_len;
    if (buffer_len >= 16) {
        cmd[0] = MIFARE_CMD_WRITE;
        cmd[1] = (uint8_t)blockno;
        memcpy(cmd + 2, buffer, 16);
        cmd_len = 18;
    } else if (buffer_len >= 4) {
        cmd[0] = MIFARE_ULTRALIGHT_CMD_WRITE;
        cmd[1] = (uint8_t)blockno;
        memcpy(cmd + 2, buffer, 4);
        cmd_len = 6;
    } else {
        return -1;
    }

    size_t response_len = 0;
    return pn532_in_data_exchange(pn532, cmd, cmd_len, NULL, &response_len, (uint16_t)pn532->timeout_ms) ? 0 : -2;
}

bool pn532_mifare_value_read(pn532_t *pn532, uint8_t blockno, int32_t *value)
{
    uint8_t buf[16];
    if (value == NULL || !pn532_mifare_block_read(pn532, blockno, buf, sizeof(buf))) {
        return false;
    }
    /*
     * MIFARE Classic value block layout:
     *   bytes 0..3   : value (LSB first)
     *   bytes 4..7   : ~value
     *   bytes 8..11  : value (again)
     *   byte  12     : addr
     *   byte  13     : ~addr
     *   byte  14     : addr
     *   byte  15     : ~addr
     */
    uint32_t v0 = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    uint32_t v2 = (uint32_t)buf[8] | ((uint32_t)buf[9] << 8) | ((uint32_t)buf[10] << 16) | ((uint32_t)buf[11] << 24);
    uint32_t inv = ~((uint32_t)buf[4] | ((uint32_t)buf[5] << 8) | ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 24));
    if (v0 != v2 || v0 != inv) {
        ESP_LOGE(TAG, "pn532_mifare_value_read: invalid value block format");
        return false;
    }
    if ((uint8_t)(buf[12] ^ 0xFF) != buf[13] || (uint8_t)(buf[14] ^ 0xFF) != buf[15] || buf[12] != buf[14]) {
        ESP_LOGE(TAG, "pn532_mifare_value_read: invalid address bytes");
        return false;
    }
    *value = (int32_t)v0;
    return true;
}

bool pn532_mifare_value_write(pn532_t *pn532, uint8_t blockno, int32_t value, uint8_t addr)
{
    uint8_t buf[16];
    uint32_t v = (uint32_t)value;
    uint32_t i = ~v;

    buf[0]  = (uint8_t)(v & 0xFF);
    buf[1]  = (uint8_t)((v >> 8) & 0xFF);
    buf[2]  = (uint8_t)((v >> 16) & 0xFF);
    buf[3]  = (uint8_t)((v >> 24) & 0xFF);
    buf[4]  = (uint8_t)(i & 0xFF);
    buf[5]  = (uint8_t)((i >> 8) & 0xFF);
    buf[6]  = (uint8_t)((i >> 16) & 0xFF);
    buf[7]  = (uint8_t)((i >> 24) & 0xFF);
    buf[8]  = buf[0];
    buf[9]  = buf[1];
    buf[10] = buf[2];
    buf[11] = buf[3];
    buf[12] = addr;
    buf[13] = (uint8_t)~addr;
    buf[14] = addr;
    buf[15] = (uint8_t)~addr;

    return pn532_mifare_block_write(pn532, blockno, buf, sizeof(buf)) == 0;
}

static bool pn532_mifare_value_op(pn532_t *pn532, uint8_t cmd, uint8_t blockno, uint32_t delta)
{
    /*
     * Increment / Decrement / Restore are 2-step MIFARE Classic operations:
     * the host issues the value command (and a 4-byte argument for INC/DEC)
     * which the card ACKs, then the host issues TRANSFER to commit the
     * internal accumulator to the destination block. PN532 InDataExchange
     * does not chain these automatically — we do it explicitly.
     */
    uint8_t op[6];
    size_t op_len;

    op[0] = cmd;
    op[1] = blockno;
    if (cmd == MIFARE_CMD_INCREMENT || cmd == MIFARE_CMD_DECREMENT) {
        op[2] = (uint8_t)(delta & 0xFF);
        op[3] = (uint8_t)((delta >> 8) & 0xFF);
        op[4] = (uint8_t)((delta >> 16) & 0xFF);
        op[5] = (uint8_t)((delta >> 24) & 0xFF);
        op_len = 6;
    } else {
        /* RESTORE requires a 4-byte dummy operand. */
        op[2] = 0;
        op[3] = 0;
        op[4] = 0;
        op[5] = 0;
        op_len = 6;
    }

    size_t response_len = 0;
    return pn532_in_data_exchange(pn532, op, op_len, NULL, &response_len, (uint16_t)pn532->timeout_ms);
}

bool pn532_mifare_increment(pn532_t *pn532, uint8_t blockno, uint32_t delta)
{
    return pn532_mifare_value_op(pn532, MIFARE_CMD_INCREMENT, blockno, delta);
}

bool pn532_mifare_decrement(pn532_t *pn532, uint8_t blockno, uint32_t delta)
{
    return pn532_mifare_value_op(pn532, MIFARE_CMD_DECREMENT, blockno, delta);
}

bool pn532_mifare_restore(pn532_t *pn532, uint8_t blockno)
{
    return pn532_mifare_value_op(pn532, MIFARE_CMD_STORE, blockno, 0);
}

bool pn532_mifare_transfer(pn532_t *pn532, uint8_t blockno)
{
    uint8_t op[2] = {MIFARE_CMD_TRANSFER, blockno};
    size_t response_len = 0;
    return pn532_in_data_exchange(pn532, op, sizeof(op), NULL, &response_len, (uint16_t)pn532->timeout_ms);
}
