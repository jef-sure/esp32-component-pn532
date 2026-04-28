#include "pn532-internal.h"

#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "PN532";

static const uint8_t pn532_ack[]         = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
static const uint8_t pn532_error_frame[] = {0x00, 0x00, 0xFF, 0x01, 0xFF, 0x7F, 0x81, 0x00};

#define PN532_DEFAULT_TIMEOUT_MS         500
#define PN532_SAM_MODE_NORMAL            0x01
#define PN532_SAM_TIMEOUT_1S             0x14
#define PN532_SAM_IRQ_ENABLE             0x01
#define PN532_PASSIVE_ACTIVATION_RETRIES 0x05
#define PN532_STATUS_OK                  0x00
#define PN532_STATUS_RF_TIMEOUT          0x01
#define PN532_STATUS_MIFARE_ERROR_13     0x13
#define PN532_STATUS_MIFARE_ERROR_14     0x14
#define PN532_STATUS_ALREADY_SELECTED    0x27

static bool pn532_rf_configuration(pn532_t *pn532, uint8_t cfg_item, const uint8_t *config_data,
                                   size_t config_data_len);
static bool pn532_set_passive_activation_retries(pn532_t *pn532, uint8_t max_retries);
static bool pn532_set_retries(pn532_t *pn532, uint8_t max_rty_atr, uint8_t max_rty_psl,
                              uint8_t max_rty_passive_activation);
static bool pn532_sam_configuration(pn532_t *pn532, uint8_t mode, uint8_t timeout, uint8_t irq_enable);

static bool pn532_status_requires_reselect(uint8_t status)
{
    switch (status) {
    case PN532_STATUS_RF_TIMEOUT:
    case PN532_STATUS_MIFARE_ERROR_13:
    case PN532_STATUS_MIFARE_ERROR_14:
        return true;
    default:
        return false;
    }
}

static inline bool pn532_gpio_is_valid(gpio_num_t gpio)
{
    return gpio >= 0;
}

static bool pn532_restore_runtime_config(pn532_t *pn532)
{
    if (!pn532_sam_configuration(pn532, PN532_SAM_MODE_NORMAL, PN532_SAM_TIMEOUT_1S, PN532_SAM_IRQ_ENABLE)) {
        ESP_LOGE(TAG, "pn532: SAM configuration failed");
        return false;
    }
    if (!pn532_set_passive_activation_retries(pn532, PN532_PASSIVE_ACTIVATION_RETRIES)) {
        ESP_LOGE(TAG, "pn532: failed to configure passive activation retries");
        return false;
    }
    return true;
}

static bool pn532_recover_after_reset(pn532_t *pn532)
{
    if (pn532 == NULL) {
        return false;
    }

    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0 && !pn532_reset(pn532)) {
            continue;
        }

        if (pn532_get_firmware_version(pn532) == 0) {
            ESP_LOGW(TAG, "pn532: firmware version read failed after recovery reset (attempt %d)", attempt + 1);
            continue;
        }

        if (pn532_restore_runtime_config(pn532)) {
            return true;
        }

        ESP_LOGW(TAG, "pn532: runtime configuration restore failed after recovery reset (attempt %d)", attempt + 1);
    }

    return false;
}

void pn532_delay_ms(int ms)
{
    int64_t start = esp_timer_get_time();
    while ((esp_timer_get_time() - start) < (ms * 1000)) {
        vTaskDelay(1);
    }
}

void pn532_bus_destroy(pn532_bus_t *bus)
{
    if (bus != NULL && bus->destroy != NULL) {
        bus->destroy(bus);
    }
}

static bool pn532_write_frame(pn532_t *pn532, uint8_t command, const uint8_t *params, size_t params_len)
{
    size_t payload_len  = params_len + 2;
    size_t required_len = payload_len + ((payload_len < 0xFF) ? 7 : 10);
    if (required_len > PN532_MAX_BUF_SIZE) {
        ESP_LOGE(TAG, "pn532_write_frame: frame too large (%u bytes)", (unsigned int)required_len);
        return false;
    }

    uint8_t  checksum = 0;
    uint8_t *cursor   = pn532->send_buf;

    *cursor++ = PN532_PREAMBLE;
    *cursor++ = PN532_STARTCODE1;
    *cursor++ = PN532_STARTCODE2;

    if (payload_len < 0xFF) {
        *cursor++ = (uint8_t)payload_len;
        *cursor++ = (uint8_t)(0u - (uint8_t)payload_len);
    } else {
        uint8_t payload_msb = (uint8_t)(payload_len >> 8);
        uint8_t payload_lsb = (uint8_t)(payload_len & 0xFF);
        *cursor++           = 0xFF;
        *cursor++           = 0xFF;
        *cursor++           = payload_msb;
        *cursor++           = payload_lsb;
        *cursor++           = (uint8_t)(0u - payload_msb - payload_lsb);
    }

    *cursor++ = PN532_HOSTTOPN532;
    checksum += PN532_HOSTTOPN532;
    *cursor++ = command;
    checksum += command;

    for (size_t i = 0; i < params_len; i++) {
        *cursor++ = params[i];
        checksum += params[i];
    }

    *cursor++ = (uint8_t)(0u - checksum);
    *cursor++ = PN532_POSTAMBLE;

    if (pn532->bus == NULL || pn532->bus->write_command == NULL) {
        ESP_LOGE(TAG, "pn532_write_frame: bus write command is not available");
        return false;
    }

    return pn532->bus->write_command(pn532->bus, pn532->send_buf, (size_t)(cursor - pn532->send_buf));
}

static bool pn532_read_data(pn532_t *pn532, uint8_t *buffer, size_t len)
{
    if (len > PN532_MAX_BUF_SIZE) {
        ESP_LOGE(TAG, "pn532_read_data: requested read exceeds buffer size");
        return false;
    }

    if (pn532->bus == NULL || pn532->bus->read_data == NULL) {
        ESP_LOGE(TAG, "pn532_read_data: bus read operation is not available");
        return false;
    }

    return pn532->bus->read_data(pn532->bus, buffer, len);
}

static bool pn532_is_ready(pn532_t *pn532)
{
    if (pn532->bus == NULL || pn532->bus->is_ready == NULL) {
        ESP_LOGE(TAG, "pn532_is_ready: bus ready check is not available");
        return false;
    }

    return pn532->bus->is_ready(pn532->bus);
}

static bool pn532_wait_ready(pn532_t *pn532, uint16_t timeout)
{
    uint16_t waited = 0;
    while (!pn532_is_ready(pn532)) {
        if (timeout != 0) {
            waited += 10;
            if (waited > timeout) {
                return false;
            }
        }
        pn532_delay_ms(10);
    }

    return true;
}

static bool pn532_read_ack(pn532_t *pn532)
{
    if (!pn532_read_data(pn532, pn532->recv_buf, sizeof(pn532_ack))) {
        return false;
    }
    return memcmp(pn532->recv_buf, pn532_ack, sizeof(pn532_ack)) == 0;
}

static void pn532_abort_current_command(pn532_t *pn532)
{
    if (pn532 == NULL || pn532->bus == NULL || pn532->bus->write_command == NULL) {
        return;
    }

    if (pn532->bus->wake != NULL) {
        pn532->bus->wake(pn532->bus);
    }

    /* UM0701-02 abort procedure: host sends an ACK frame to stop the current
     * command. Use this only after a timeout; sending it during normal wake-up
     * aborts the next command instead. */
    (void)pn532->bus->write_command(pn532->bus, pn532_ack, sizeof(pn532_ack));
    pn532_delay_ms(2);

    if (pn532->bus->is_ready != NULL && pn532->bus->read_data != NULL && pn532->bus->is_ready(pn532->bus)) {
        uint8_t drain[16];
        (void)pn532->bus->read_data(pn532->bus, drain, sizeof(drain));
    }

    pn532->inListedTag    = 0;
    pn532->is_rf_on       = false;
    pn532->session_opened = false;
}

static void pn532_recover_after_timeout(pn532_t *pn532, uint8_t command, const char *phase)
{
    ESP_LOGW(TAG, "pn532_execute_command: recovering after command 0x%02X %s timeout", command, phase);
    pn532_abort_current_command(pn532);
    if (pn532 != NULL && pn532_gpio_is_valid(pn532->rst)) {
        pn532->recovery_in_progress = true;
        (void)pn532_reset(pn532);
        if (!pn532_recover_after_reset(pn532)) {
            ESP_LOGE(TAG, "pn532_execute_command: failed to restore configuration after timeout reset");
        }
        pn532->recovery_in_progress = false;
    }
}

static bool pn532_read_response_frame(pn532_t *pn532, uint8_t expected_response, size_t *payload_offset,
                                      size_t *payload_len)
{
    if (!pn532_read_data(pn532, pn532->recv_buf, PN532_MAX_BUF_SIZE)) {
        return false;
    }

    if (memcmp(pn532->recv_buf, pn532_error_frame, sizeof(pn532_error_frame)) == 0) {
        ESP_LOGE(TAG, "pn532_read_response_frame: PN532 returned an error frame for command 0x%02X",
                 expected_response - 1);
        return false;
    }

    if (pn532->recv_buf[0] != PN532_PREAMBLE || pn532->recv_buf[1] != PN532_STARTCODE1 ||
        pn532->recv_buf[2] != PN532_STARTCODE2) {
        ESP_LOGE(TAG, "pn532_read_response_frame: invalid frame header");
        return false;
    }

    size_t frame_header_len;
    size_t frame_payload_len;
    size_t dcs_index;
    size_t postamble_index;
    if (pn532->recv_buf[3] == 0xFF && pn532->recv_buf[4] == 0xFF) {
        frame_header_len  = 8;
        frame_payload_len = ((size_t)pn532->recv_buf[5] << 8) | pn532->recv_buf[6];
        if ((uint8_t)(pn532->recv_buf[5] + pn532->recv_buf[6] + pn532->recv_buf[7]) != 0) {
            ESP_LOGE(TAG, "pn532_read_response_frame: invalid extended length checksum");
            return false;
        }
    } else {
        frame_header_len  = 5;
        frame_payload_len = pn532->recv_buf[3];
        if ((uint8_t)(pn532->recv_buf[3] + pn532->recv_buf[4]) != 0) {
            ESP_LOGE(TAG, "pn532_read_response_frame: invalid frame length checksum");
            return false;
        }
    }

    dcs_index       = frame_header_len + frame_payload_len;
    postamble_index = dcs_index + 1;
    if (postamble_index >= PN532_MAX_BUF_SIZE) {
        ESP_LOGE(TAG, "pn532_read_response_frame: frame length exceeds buffer");
        return false;
    }

    uint8_t checksum = 0;
    for (size_t i = frame_header_len; i <= dcs_index; i++) {
        checksum += pn532->recv_buf[i];
    }
    if (checksum != 0) {
        ESP_LOGE(TAG, "pn532_read_response_frame: invalid data checksum");
        return false;
    }

    if (pn532->recv_buf[postamble_index] != PN532_POSTAMBLE) {
        ESP_LOGE(TAG, "pn532_read_response_frame: invalid postamble");
        return false;
    }

    if (frame_payload_len < 2) {
        ESP_LOGE(TAG, "pn532_read_response_frame: truncated payload");
        return false;
    }
    if (pn532->recv_buf[frame_header_len] != PN532_PN532TOHOST) {
        ESP_LOGE(TAG, "pn532_read_response_frame: invalid frame direction");
        return false;
    }
    if (pn532->recv_buf[frame_header_len + 1] != expected_response) {
        ESP_LOGE(TAG, "pn532_read_response_frame: unexpected response 0x%02X for command 0x%02X",
                 pn532->recv_buf[frame_header_len + 1], expected_response - 1);
        return false;
    }

    *payload_offset = frame_header_len + 2;
    *payload_len    = frame_payload_len - 2;
    return true;
}

bool pn532_execute_command(      //
    pn532_t       *pn532,        //
    uint8_t        command,      //
    const uint8_t *params,       //
    size_t         params_len,   //
    uint8_t       *response,     //
    size_t        *response_len, //
    uint16_t       timeout       //
)
{
    if (response != NULL && response_len == NULL) {
        ESP_LOGE(TAG, "pn532_execute_command: response_len is required when response buffer is provided");
        return false;
    }

    if (!pn532_write_frame(pn532, command, params, params_len)) {
        return false;
    }

    if (!pn532_wait_ready(pn532, timeout)) {
        ESP_LOGW(TAG, "pn532_execute_command: command 0x%02X timed out waiting for ACK", command);
        if (pn532 == NULL || !pn532->recovery_in_progress) {
            pn532_recover_after_timeout(pn532, command, "ACK");
        }
        return false;
    }
    if (!pn532_read_ack(pn532)) {
        ESP_LOGE(TAG, "pn532_execute_command: invalid ACK for command 0x%02X", command);
        pn532_abort_current_command(pn532);
        return false;
    }
    if (!pn532_wait_ready(pn532, timeout)) {
        ESP_LOGW(TAG, "pn532_execute_command: command 0x%02X timed out waiting for response", command);
        if (pn532 == NULL || !pn532->recovery_in_progress) {
            pn532_recover_after_timeout(pn532, command, "response");
        }
        return false;
    }

    size_t payload_offset = 0;
    size_t payload_len    = 0;
    if (!pn532_read_response_frame(pn532, (uint8_t)(command + 1), &payload_offset, &payload_len)) {
        return false;
    }

    if (response_len != NULL) {
        size_t capacity = (response != NULL) ? *response_len : 0;
        if (response != NULL && payload_len > capacity) {
            *response_len = payload_len;
            ESP_LOGE(TAG, "pn532_execute_command: response buffer too small for command 0x%02X", command);
            return false;
        }
        if (response != NULL && payload_len > 0) {
            memcpy(response, pn532->recv_buf + payload_offset, payload_len);
        }
        *response_len = payload_len;
    }

    return true;
}

uint32_t pn532_get_firmware_version(pn532_t *pn532)
{
    uint8_t response[4];
    size_t  response_len = sizeof(response);
    if (!pn532_execute_command(pn532, PN532_COMMAND_GETFIRMWAREVERSION, NULL, 0, response, &response_len,
                               (uint16_t)pn532->timeout_ms) ||
        response_len != sizeof(response)) {
        ESP_LOGE(TAG, "pn532_get_firmware_version: command failed");
        return 0;
    }

    return ((uint32_t)response[0] << 24) | ((uint32_t)response[1] << 16) | ((uint32_t)response[2] << 8) | response[3];
}

bool pn532_reset(pn532_t *pn532)
{
    if (pn532_gpio_is_valid(pn532->rst)) {
        gpio_set_level(pn532->rst, 0);
        pn532_delay_ms(20);
        gpio_set_level(pn532->rst, 1);
    }

    pn532_delay_ms(100);
    pn532->inListedTag    = 0;
    pn532->is_rf_on       = false;
    pn532->session_opened = false;

    /* Some buses (SPI) need a wake-up sequence after a hard reset before the
     * chip will respond to commands. */
    if (pn532->bus != NULL && pn532->bus->wake != NULL) {
        pn532->bus->wake(pn532->bus);
    }
    return true;
}

pn532_t *pn532_init(pn532_bus_t *bus, gpio_num_t irq, gpio_num_t rst)
{
    if (bus == NULL) {
        return NULL;
    }

    pn532_t *pn532 = calloc(1, sizeof(*pn532));
    if (pn532 == NULL) {
        return NULL;
    }

    pn532->send_buf = calloc(PN532_MAX_BUF_SIZE, sizeof(uint8_t));
    pn532->recv_buf = calloc(PN532_MAX_BUF_SIZE, sizeof(uint8_t));
    if (pn532->send_buf == NULL || pn532->recv_buf == NULL) {
        free(pn532->send_buf);
        free(pn532->recv_buf);
        free(pn532);
        ESP_LOGE(TAG, "pn532: failed to allocate transport buffers");
        return NULL;
    }

    pn532->bus        = bus;
    pn532->irq        = irq;
    pn532->rst        = rst;
    pn532->rf_config  = PN532_MIFARE_ISO14443A;
    pn532->timeout_ms = PN532_DEFAULT_TIMEOUT_MS;

    if (pn532_gpio_is_valid(rst)) {
        gpio_set_direction(rst, GPIO_MODE_OUTPUT);
        gpio_set_level(rst, 1);
    }
    if (pn532_gpio_is_valid(irq)) {
        gpio_set_direction(irq, GPIO_MODE_INPUT);
    }

    if (!pn532_reset(pn532)) {
        pn532_deinit(pn532, false);
        return NULL;
    }

    /*
     * Get firmware version with retries. The chip occasionally misses the
     * first command after power-on (still booting / SPI not yet woken).
     * Hard-reset and retry a few times before giving up.
     */
    bool fw_ok = false;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (pn532_get_firmware_version(pn532) != 0) {
            fw_ok = true;
            break;
        }
        ESP_LOGW(TAG, "pn532: firmware version read failed (attempt %d), resetting", attempt + 1);
        pn532_reset(pn532);
    }
    if (!fw_ok) {
        ESP_LOGE(TAG, "pn532: failed to read firmware version during init");
        pn532_deinit(pn532, false);
        return NULL;
    }

    /*
     * SAMConfiguration parameters per UM0701-02 §7.2.10:
     *   Mode      = 0x01 (normal mode, SAM not used)
     *   Timeout   = 0x14 (20 × 50 ms = 1 s; only used in virtual-card mode)
     *   IRQ Enable= 0x01 (IRQ pin asserted on response ready)
     */
    if (!pn532_restore_runtime_config(pn532)) {
        ESP_LOGE(TAG, "pn532: runtime configuration failed during init");
        pn532_deinit(pn532, false);
        return NULL;
    }

    return pn532;
}

void pn532_deinit(pn532_t *pn532, bool free_bus)
{
    if (pn532 == NULL) {
        return;
    }

    pn532_bus_t *bus = pn532->bus;
    free(pn532->send_buf);
    free(pn532->recv_buf);
    free(pn532);

    if (free_bus) {
        pn532_bus_destroy(bus);
    }
}

bool pn532_set_rf_field(pn532_t *pn532, bool enabled)
{
    const uint8_t params[]     = {0x01, enabled ? 0x03 : 0x02};
    size_t        response_len = 0;
    bool          ok           = pn532_execute_command(pn532, PN532_COMMAND_RFCONFIGURATION, params, sizeof(params), NULL,
                                                       &response_len, (uint16_t)pn532->timeout_ms);
    if (ok && response_len == 0) {
        pn532->is_rf_on = enabled;
    }
    return ok && response_len == 0;
}

bool pn532_set_rf_on(pn532_t *pn532)
{
    return pn532_set_rf_field(pn532, true);
}

bool pn532_set_rf_off(pn532_t *pn532)
{
    return pn532_set_rf_field(pn532, false);
}

static bool pn532_rf_configuration(pn532_t *pn532, uint8_t cfg_item, const uint8_t *config_data, size_t config_data_len)
{
    if (pn532 == NULL || config_data == NULL || config_data_len == 0 || config_data_len > PN532_MAX_BUF_SIZE - 16) {
        return false;
    }

    uint8_t params[PN532_MAX_BUF_SIZE];
    params[0] = cfg_item;
    memcpy(params + 1, config_data, config_data_len);

    size_t response_len = 0;
    return pn532_execute_command(pn532, PN532_COMMAND_RFCONFIGURATION, params, config_data_len + 1, NULL, &response_len,
                                 (uint16_t)pn532->timeout_ms) &&
           response_len == 0;
}

static bool pn532_set_passive_activation_retries(pn532_t *pn532, uint8_t max_retries)
{
    return pn532_set_retries(pn532, 0xFF, 0x01, max_retries);
}

static bool pn532_set_retries(pn532_t *pn532, uint8_t max_rty_atr, uint8_t max_rty_psl,
                              uint8_t max_rty_passive_activation)
{
    const uint8_t cfg[] = {max_rty_atr, max_rty_psl, max_rty_passive_activation};
    return pn532_rf_configuration(pn532, 0x05, cfg, sizeof(cfg));
}

static bool pn532_sam_configuration(pn532_t *pn532, uint8_t mode, uint8_t timeout, uint8_t irq_enable)
{
    const uint8_t params[]     = {mode, timeout, irq_enable};
    size_t        response_len = 0;
    return pn532_execute_command(pn532, PN532_COMMAND_SAMCONFIGURATION, params, sizeof(params), NULL, &response_len,
                                 (uint16_t)pn532->timeout_ms) &&
           response_len == 0;
}

bool pn532_release_target(pn532_t *pn532)
{
    if (pn532 == NULL) {
        return false;
    }

    if (pn532->inListedTag == 0) {
        return true;
    }

    uint8_t params[] = {pn532->inListedTag};
    uint8_t response[4];
    size_t  response_len = sizeof(response);
    bool    ok = pn532_execute_command(pn532, PN532_COMMAND_INRELEASE, params, sizeof(params), response, &response_len,
                                       (uint16_t)pn532->timeout_ms);
    if (ok) {
        pn532->inListedTag    = 0;
        pn532->session_opened = false;
    }
    /* Status byte (response[0]) of 0x00 means success; non-zero is reported but we
     * still consider the target released because the chip won't keep activation
     * after issuing InRelease. */
    return ok;
}

bool pn532_in_data_exchange(pn532_t *pn532, const uint8_t *data, size_t data_len, uint8_t *response,
                            size_t *response_len, uint16_t timeout)
{
    if (data == NULL || data_len == 0 || data_len + 1 > PN532_MAX_BUF_SIZE) {
        return false;
    }

    if (pn532->inListedTag == 0) {
        ESP_LOGE(TAG, "pn532_in_data_exchange: no target selected");
        return false;
    }

    uint8_t params[PN532_MAX_BUF_SIZE];
    params[0] = pn532->inListedTag;
    memcpy(params + 1, data, data_len);

    uint8_t raw_response[PN532_MAX_BUF_SIZE];
    size_t  raw_response_len = sizeof(raw_response);
    if (!pn532_execute_command(pn532, PN532_COMMAND_INDATAEXCHANGE, params, data_len + 1, raw_response,
                               &raw_response_len, timeout)) {
        return false;
    }
    if (raw_response_len == 0) {
        ESP_LOGE(TAG, "pn532_in_data_exchange: empty response");
        return false;
    }
    if (raw_response[0] != PN532_STATUS_OK) {
        /*
         * NXP's TAMA stack reports 0x01/0x13/0x14 as RF timeout style errors
         * from transceive, but it does not discard the target handle there.
         * Keep the listed target number and only mark the session as needing a
         * fresh InSelect before the next exchange.
         */
        if (pn532_status_requires_reselect(raw_response[0])) {
            if (raw_response[0] == PN532_STATUS_RF_TIMEOUT) {
                pn532->is_rf_on = false;
            }
            pn532->session_opened = false;
        }
        ESP_LOGD(TAG, "pn532_in_data_exchange: PN532 status 0x%02X", raw_response[0]);
        return false;
    }

    size_t payload_len = raw_response_len - 1;
    if (response_len != NULL) {
        size_t capacity = (response != NULL) ? *response_len : 0;
        if (response != NULL && payload_len > capacity) {
            *response_len = payload_len;
            return false;
        }
        if (response != NULL && payload_len > 0) {
            memcpy(response, raw_response + 1, payload_len);
        }
        *response_len = payload_len;
    }

    return true;
}

bool pn532_in_select(pn532_t *pn532, uint8_t target_number)
{
    const uint8_t params[]   = {target_number};
    uint8_t       status[1]  = {0};
    size_t        status_len = sizeof(status);
    if (!pn532_execute_command(pn532, PN532_COMMAND_INSELECT, params, sizeof(params), status, &status_len,
                               (uint16_t)pn532->timeout_ms)) {
        pn532->session_opened = false;
        return false;
    }
    if (status_len == 0) {
        ESP_LOGE(TAG, "pn532_in_select: empty response");
        pn532->session_opened = false;
        return false;
    }
    if (status[0] != PN532_STATUS_OK && status[0] != PN532_STATUS_ALREADY_SELECTED) {
        ESP_LOGE(TAG, "pn532_in_select: status 0x%02X", status[0]);
        pn532->session_opened = false;
        return false;
    }
    pn532->inListedTag    = target_number;
    pn532->session_opened = true;
    return true;
}
