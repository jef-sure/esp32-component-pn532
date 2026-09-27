#include "pn532.h"

#include <string.h>

esp_err_t pn532_apdu_parse_command(const uint8_t *buffer, size_t length, pn532_apdu_command_t *command)
{
    if (command == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(command, 0, sizeof(*command));

    if (buffer == NULL || length < 4) {
        return ESP_ERR_INVALID_ARG;
    }

    command->cla = buffer[0];
    command->ins = buffer[1];
    command->p1  = buffer[2];
    command->p2  = buffer[3];

    if (length == 4) {
        return ESP_OK;
    }

    if (length == 5) {
        command->has_le = true;
        command->le = buffer[4] == 0u ? 256u : buffer[4];
        return ESP_OK;
    }

    if (buffer[4] == 0u) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    size_t lc = (size_t)buffer[4];
    size_t expected = 5u + lc;
    if (length < expected) {
        return ESP_ERR_INVALID_ARG;
    }

    command->data = &buffer[5];
    command->data_len = lc;

    if (length == expected) {
        return ESP_OK;
    }

    if (length == expected + 1u) {
        command->has_le = true;
        command->le = buffer[expected] == 0u ? 256u : buffer[expected];
        return ESP_OK;
    }

    return ESP_ERR_INVALID_ARG;
}

esp_err_t pn532_apdu_parse_response(const uint8_t *buffer, size_t length, pn532_apdu_response_t *response)
{
    if (response == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(response, 0, sizeof(*response));

    if (buffer == NULL || length < 2) {
        return ESP_ERR_INVALID_ARG;
    }

    response->data = buffer;
    response->data_len = length - 2u;
    response->sw1 = buffer[length - 2u];
    response->sw2 = buffer[length - 1u];
    return ESP_OK;
}

uint16_t pn532_apdu_get_status(const pn532_apdu_response_t *response)
{
    return response == NULL ? 0u : (uint16_t)(((uint16_t)response->sw1 << 8) | response->sw2);
}

esp_err_t pn532_apdu_build_response(uint8_t *buffer, size_t buffer_size, const uint8_t *data, size_t data_len,
                                    uint8_t sw1, uint8_t sw2, size_t *response_len)
{
    if (response_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *response_len = 0;

    if (buffer == NULL || (data == NULL && data_len != 0)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (buffer_size < 2u || data_len > buffer_size - 2u) {
        return ESP_ERR_NO_MEM;
    }

    if (data_len > 0) {
        memcpy(buffer, data, data_len);
    }
    buffer[data_len] = sw1;
    buffer[data_len + 1u] = sw2;
    *response_len = data_len + 2u;
    return ESP_OK;
}