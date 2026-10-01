#include "pn532-internal.h"

#include <stdlib.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_attr.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

static const char *TAG = "PN532";

#define PN532_IRQ_QUEUE_DEPTH 4

static void IRAM_ATTR pn532_irq_isr_handler(void *arg)
{
    pn532_t *pn532 = (pn532_t *)arg;
    if (pn532 == NULL || pn532->irq_queue == NULL) {
        return;
    }
    uint8_t    evt      = 1;
    BaseType_t hp_woken = pdFALSE;
    (void)xQueueSendFromISR(pn532->irq_queue, &evt, &hp_woken);
    if (hp_woken == pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

static const uint8_t pn532_ack[]         = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
static const uint8_t pn532_nack[]        = {0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00};
static const uint8_t pn532_error_frame[] = {0x00, 0x00, 0xFF, 0x01, 0xFF, 0x7F, 0x81, 0x00};

#define PN532_DEFAULT_TIMEOUT_MS         500
#define PN532_NACK_RETRIES               2
#define PN532_SAM_MODE_NORMAL            0x01
#define PN532_SAM_TIMEOUT_1S             0x14
#define PN532_SAM_IRQ_ENABLE             0x01
#define PN532_PASSIVE_ACTIVATION_RETRIES 0x05
#define PN532_STATUS_OK                  0x00
#define PN532_STATUS_RF_TIMEOUT          0x01
#define PN532_STATUS_MIFARE_ERROR_13     0x13
#define PN532_STATUS_MIFARE_ERROR_14     0x14
#define PN532_STATUS_TARGET_NOT_KNOWN    0x27
#define PN532_STATUS_NAD_MASK            0x80
#define PN532_STATUS_MI_MASK             0x40
#define PN532_STATUS_ERROR_MASK          0x3F
#define PN532_MI_MAX_CHAIN_ROUNDS        64

static bool pn532_rf_configuration(pn532_t *pn532, uint8_t cfg_item, const uint8_t *config_data,
                                   size_t config_data_len);
static bool pn532_sam_configuration(pn532_t *pn532, uint8_t mode, uint8_t timeout, uint8_t irq_enable);
static void pn532_apply_rf_settle_delay(pn532_t *pn532);

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
    if (pn532 != NULL && pn532->isr_installed && pn532->irq_queue != NULL) {
        /* Check the line first: the IRQ may already be asserted from before
         * this call (an edge we never re-armed for). P70_IRQ low means a
         * response is pending (UM0701-02 §6.3); the bus check stays as a
         * fallback because IRQ is only driven once SAMConfiguration enables it.
         * Without this pre-check xQueueReceive with timeout=0 blocks forever. */
        if (gpio_get_level(pn532->irq) == 0 || pn532_is_ready(pn532)) {
            return true;
        }
        uint8_t    evt;
        TickType_t ticks = (timeout == 0) ? portMAX_DELAY : pdMS_TO_TICKS(timeout);
        if (xQueueReceive(pn532->irq_queue, &evt, ticks) == pdTRUE) {
            return true;
        }
        /* Final check: covers the race where the edge fired between the
         * pre-check and the queue wait but was consumed elsewhere. */
        return gpio_get_level(pn532->irq) == 0 || pn532_is_ready(pn532);
    }

    /* Poll once per tick against a wall-clock deadline: readiness is seen
     * within one tick instead of a fixed 10 ms step, and the timeout stays
     * accurate regardless of CONFIG_FREERTOS_HZ. */
    int64_t deadline_us = esp_timer_get_time() + (int64_t)timeout * 1000;
    while (!pn532_is_ready(pn532)) {
        if (timeout != 0 && esp_timer_get_time() > deadline_us) {
            return false;
        }
        vTaskDelay(1);
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

static void pn532_apply_rf_settle_delay(pn532_t *pn532)
{
    if (pn532 == NULL || pn532->rf_settle_delay_ms == 0) {
        return;
    }
    /* Give the field collapse time to release a HALT-state card before the
     * next InListPassiveTarget restarts the field. The default mirrors the
     * two-reader interleaving measured on hardware. */
    pn532_delay_ms(pn532->rf_settle_delay_ms);
}

void pn532_abort_current_command(pn532_t *pn532)
{
    if (pn532 == NULL || pn532->bus == NULL || pn532->bus->write_command == NULL) {
        return;
    }

    /* UM0701-02 abort procedure: host sends an ACK frame to stop the current
     * command. Use this only after a timeout; sending it during normal wake-up
     * aborts the next command instead. */
    (void)pn532->bus->write_command(pn532->bus, pn532_ack, sizeof(pn532_ack));
    pn532_delay_ms(2);

    /* Drain the full PN532 buffer: an aborted InListPassiveTarget with two
     * cards can leave ~65 bytes of response behind. A short 16-byte read
     * would leave the tail in the FIFO and corrupt the next frame. */
    if (pn532->bus->is_ready != NULL && pn532->bus->read_data != NULL) {
        size_t guard = 0;
        while (pn532->bus->is_ready(pn532->bus) && guard++ < PN532_MAX_BUF_SIZE) {
            if (!pn532->bus->read_data(pn532->bus, pn532->recv_buf, PN532_MAX_BUF_SIZE)) {
                break;
            }
        }
    }

    pn532->inListedTag    = 0;
    pn532->is_rf_on       = false;
    pn532->session_opened = false;
}

static void pn532_recover_after_timeout(pn532_t *pn532, uint8_t command, const char *phase)
{
    ESP_LOGW(TAG, "pn532_execute_command: recovering after command 0x%02X %s timeout", command, phase);
    pn532_abort_current_command(pn532);
}

typedef enum
{
    PN532_FRAME_OK,
    PN532_FRAME_CORRUPT,  /* damaged on the line: the PN532 can resend it on NACK */
    PN532_FRAME_REJECTED, /* intact but not the expected answer */
} pn532_frame_result_t;

static pn532_frame_result_t pn532_read_response_frame(pn532_t *pn532, uint8_t expected_response,
                                                      size_t *payload_offset, size_t *payload_len)
{
    if (!pn532_read_data(pn532, pn532->recv_buf, PN532_MAX_BUF_SIZE)) {
        return PN532_FRAME_CORRUPT;
    }

    if (memcmp(pn532->recv_buf, pn532_error_frame, sizeof(pn532_error_frame)) == 0) {
        ESP_LOGE(TAG, "pn532_read_response_frame: PN532 returned an error frame for command 0x%02X",
                 expected_response - 1);
        return PN532_FRAME_REJECTED;
    }

    if (pn532->recv_buf[0] != PN532_PREAMBLE || pn532->recv_buf[1] != PN532_STARTCODE1 ||
        pn532->recv_buf[2] != PN532_STARTCODE2) {
        ESP_LOGE(TAG, "pn532_read_response_frame: invalid frame header");
        return PN532_FRAME_CORRUPT;
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
            return PN532_FRAME_CORRUPT;
        }
    } else {
        frame_header_len  = 5;
        frame_payload_len = pn532->recv_buf[3];
        if ((uint8_t)(pn532->recv_buf[3] + pn532->recv_buf[4]) != 0) {
            ESP_LOGE(TAG, "pn532_read_response_frame: invalid frame length checksum");
            return PN532_FRAME_CORRUPT;
        }
    }

    dcs_index       = frame_header_len + frame_payload_len;
    postamble_index = dcs_index + 1;
    if (postamble_index >= PN532_MAX_BUF_SIZE) {
        ESP_LOGE(TAG, "pn532_read_response_frame: frame length exceeds buffer");
        return PN532_FRAME_CORRUPT;
    }

    uint8_t checksum = 0;
    for (size_t i = frame_header_len; i <= dcs_index; i++) {
        checksum += pn532->recv_buf[i];
    }
    if (checksum != 0) {
        ESP_LOGE(TAG, "pn532_read_response_frame: invalid data checksum");
        return PN532_FRAME_CORRUPT;
    }

    if (pn532->recv_buf[postamble_index] != PN532_POSTAMBLE) {
        ESP_LOGE(TAG, "pn532_read_response_frame: invalid postamble");
        return PN532_FRAME_CORRUPT;
    }

    if (frame_payload_len < 2) {
        ESP_LOGE(TAG, "pn532_read_response_frame: truncated payload");
        return PN532_FRAME_REJECTED;
    }
    if (pn532->recv_buf[frame_header_len] != PN532_PN532TOHOST) {
        ESP_LOGE(TAG, "pn532_read_response_frame: invalid frame direction");
        return PN532_FRAME_REJECTED;
    }
    if (pn532->recv_buf[frame_header_len + 1] != expected_response) {
        ESP_LOGE(TAG, "pn532_read_response_frame: unexpected response 0x%02X for command 0x%02X",
                 pn532->recv_buf[frame_header_len + 1], expected_response - 1);
        return PN532_FRAME_REJECTED;
    }

    *payload_offset = frame_header_len + 2;
    *payload_len    = frame_payload_len - 2;
    return PN532_FRAME_OK;
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
    if (pn532 != NULL) {
        pn532->last_command_status = PN532_COMMAND_STATUS_TRANSPORT_ERROR;
    }
    if (response != NULL && response_len == NULL) {
        ESP_LOGE(TAG, "pn532_execute_command: response_len is required when response buffer is provided");
        return false;
    }

    /* Drain any stale IRQ events queued from a previous command before issuing
     * a new one, so the upcoming wait_ready() blocks on the new edge. */
    if (pn532 != NULL && pn532->isr_installed && pn532->irq_queue != NULL) {
        xQueueReset(pn532->irq_queue);
    }

    if (!pn532_write_frame(pn532, command, params, params_len)) {
        return false;
    }

    /* ACK phase: the PN532 acknowledges a command within a few ms. Waiting the
     * full response timeout here only masks a dead transport, so the ACK gets
     * its own short budget (NXP TAMA uses 10 ms; we keep headroom for slow
     * SPI/I2C clocking of the frame). A miss here means the transport or the
     * chip is wedged — not an RF/card problem. */
    if (!pn532_wait_ready(pn532, pn532->ack_timeout_ms)) {
        ESP_LOGE(TAG, "pn532_execute_command: no ACK for command 0x%02X within %u ms (transport not responding)",
                 command, (unsigned)pn532->ack_timeout_ms);
        pn532_recover_after_timeout(pn532, command, "ACK");
        pn532->last_command_status = PN532_COMMAND_STATUS_ACK_TIMEOUT;
        return false;
    }
    if (!pn532_read_ack(pn532)) {
        ESP_LOGE(TAG, "pn532_execute_command: invalid ACK for command 0x%02X", command);
        pn532_abort_current_command(pn532);
        return false;
    }

    /* Response phase: the full caller timeout applies. A miss here is an
     * RF/card-side problem (field collision, quiet card), not a transport
     * failure. */
    if (!pn532_wait_ready(pn532, timeout)) {
        ESP_LOGW(TAG, "pn532_execute_command: command 0x%02X timed out waiting for response", command);
        pn532_recover_after_timeout(pn532, command, "response");
        pn532->last_command_status = PN532_COMMAND_STATUS_TIMEOUT;
        return false;
    }

    size_t payload_offset = 0;
    size_t payload_len    = 0;
    pn532_frame_result_t frame =
        pn532_read_response_frame(pn532, (uint8_t)(command + 1), &payload_offset, &payload_len);

    /* UM0701-02 NACK: the PN532 resends its last response, so a frame damaged
     * on the line is recovered without re-executing a non-idempotent command. */
    for (int retry = 0; frame == PN532_FRAME_CORRUPT && retry < PN532_NACK_RETRIES; retry++) {
        ESP_LOGW(TAG, "pn532_execute_command: corrupted response to 0x%02X, requesting retransmission", command);
        if (!pn532->bus->write_command(pn532->bus, pn532_nack, sizeof(pn532_nack)) ||
            !pn532_wait_ready(pn532, pn532->ack_timeout_ms)) {
            break;
        }
        frame = pn532_read_response_frame(pn532, (uint8_t)(command + 1), &payload_offset, &payload_len);
    }
    if (frame != PN532_FRAME_OK) {
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

    pn532->last_command_status = PN532_COMMAND_STATUS_OK;
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

bool pn532_get_general_status(pn532_t *pn532, pn532_general_status_t *status)
{
    if (pn532 == NULL || status == NULL) {
        return false;
    }

    uint8_t response[16];
    size_t  response_len = sizeof(response);
    if (!pn532_execute_command(pn532, PN532_COMMAND_GETGENERALSTATUS, NULL, 0, response, &response_len,
                               (uint16_t)pn532->timeout_ms)) {
        return false;
    }

    /* UM0701-02 GetGeneralStatus response payload:
     *   Err Field NbTg [Tg BrRx BrTx Type]{NbTg} SAMstatus
     * A variable-length list with one 4-byte entry per logical target
     * (max 2), then the trailing SAM status byte. There are no bitmask
     * fields in this command — the NXP TAL ioctl passes the raw buffer
     * through undecoded (phTalTama.c, PHHALNFC_IOCTL_PN53X_GET_STATUS). */
    memset(status, 0, sizeof(*status));
    if (response_len < 3) {
        ESP_LOGE(TAG, "pn532_get_general_status: truncated status (%u bytes)", (unsigned)response_len);
        return false;
    }

    status->error         = response[0];
    status->field_present = (response[1] & 0x01) != 0;
    status->targets_count = response[2] > 2 ? 2 : response[2];

    size_t needed = 3u + 4u * (size_t)status->targets_count;
    if (response_len < needed) {
        ESP_LOGE(TAG, "pn532_get_general_status: %u target entries truncated (%u bytes)", (unsigned)status->targets_count,
                 (unsigned)response_len);
        return false;
    }

    for (uint8_t i = 0; i < status->targets_count; i++) {
        const uint8_t *entry = &response[3 + 4u * (size_t)i];
        status->targets[i].tg    = entry[0];
        status->targets[i].br_rx = entry[1];
        status->targets[i].br_tx = entry[2];
        status->targets[i].type  = entry[3];
    }

    if (response_len >= needed + 1u) {
        status->sam_status       = response[needed];
        status->sam_status_valid = true;
    }
    return true;
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

    /* Buses put the chip into low-power after reset/PowerDown: SPI wakes on
     * the NSS edge, HSU on the 0x55 0x55 preamble, I2C on a START condition.
     * Each transport provides its own wake() for this. */
    if (pn532->bus != NULL && pn532->bus->wake != NULL) {
        pn532->bus->wake(pn532->bus);
    }
    return true;
}

static bool pn532_probe_firmware(void *ctx)
{
    return pn532_get_firmware_version((pn532_t *)ctx) != 0;
}

/* Last resort when the chip stays silent: let the transport re-negotiate the link. */
static bool pn532_resync_link(pn532_t *pn532)
{
    pn532_bus_t *bus = pn532->bus;
    return bus != NULL && bus->resync != NULL && bus->resync(bus, pn532_probe_firmware, pn532);
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

    pn532->bus                = bus;
    pn532->irq                = irq;
    pn532->rst                = rst;
    pn532->rf_config          = PN532_MIFARE_ISO14443A;
    pn532->timeout_ms         = PN532_DEFAULT_TIMEOUT_MS;
    pn532->ack_timeout_ms     = PN532_ACK_TIMEOUT_MS;
    pn532->rf_settle_delay_ms = PN532_RF_SETTLE_DELAY_MS;

    if (pn532_gpio_is_valid(rst)) {
        gpio_set_direction(rst, GPIO_MODE_OUTPUT);
        gpio_set_level(rst, 1);
    }
    if (pn532_gpio_is_valid(irq)) {
        gpio_set_direction(irq, GPIO_MODE_INPUT);
        gpio_set_pull_mode(irq, GPIO_PULLUP_ONLY);
        pn532->irq_queue = xQueueCreate(PN532_IRQ_QUEUE_DEPTH, sizeof(uint8_t));
        if (pn532->irq_queue == NULL) {
            ESP_LOGE(TAG, "pn532: failed to allocate IRQ queue");
        } else {
            esp_err_t isr_err = gpio_install_isr_service(0);
            if (isr_err != ESP_OK && isr_err != ESP_ERR_INVALID_STATE) {
                ESP_LOGE(TAG, "pn532: gpio_install_isr_service failed (%s)", esp_err_to_name(isr_err));
            } else {
                gpio_set_intr_type(irq, GPIO_INTR_NEGEDGE);
                esp_err_t add_err = gpio_isr_handler_add(irq, pn532_irq_isr_handler, pn532);
                if (add_err != ESP_OK) {
                    ESP_LOGE(TAG, "pn532: gpio_isr_handler_add failed (%s)", esp_err_to_name(add_err));
                } else {
                    pn532->isr_installed = true;
                }
            }
            if (!pn532->isr_installed) {
                vQueueDelete(pn532->irq_queue);
                pn532->irq_queue = NULL;
            }
        }
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
        fw_ok = pn532_resync_link(pn532);
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

    if (pn532->isr_installed && pn532_gpio_is_valid(pn532->irq)) {
        gpio_isr_handler_remove(pn532->irq);
        pn532->isr_installed = false;
    }
    if (pn532->irq_queue != NULL) {
        vQueueDelete(pn532->irq_queue);
        pn532->irq_queue = NULL;
    }
    /* After the ISR handler is gone, so no handler can fire on a reset pin. */
    if (pn532_gpio_is_valid(pn532->irq)) {
        gpio_reset_pin(pn532->irq);
    }
    if (pn532_gpio_is_valid(pn532->rst)) {
        gpio_reset_pin(pn532->rst);
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
    bool ok = pn532_execute_command(pn532, PN532_COMMAND_RFCONFIGURATION, params, sizeof(params), NULL, &response_len,
                                    (uint16_t)pn532->timeout_ms);
    if (ok && response_len == 0) {
        pn532->is_rf_on = enabled;
        if (!enabled) {
            pn532->inListedTag    = 0;
            pn532->session_opened = false;
            /* Let the collapsed field release a HALT-state card before the
             * next InListPassiveTarget restarts the field. */
            pn532_apply_rf_settle_delay(pn532);
        }
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

void pn532_set_ack_timeout(pn532_t *pn532, uint16_t ack_timeout_ms)
{
    if (pn532 != NULL) {
        pn532->ack_timeout_ms = ack_timeout_ms;
    }
}

void pn532_set_rf_settle_delay(pn532_t *pn532, uint16_t delay_ms)
{
    if (pn532 != NULL) {
        pn532->rf_settle_delay_ms = delay_ms;
    }
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

bool pn532_set_max_retries(pn532_t *pn532, uint8_t max_rty_atr, uint8_t max_rty_psl, uint8_t max_rty_passive_activation)
{
    if (pn532 == NULL) {
        return false;
    }
    const uint8_t cfg[] = {max_rty_atr, max_rty_psl, max_rty_passive_activation};
    return pn532_rf_configuration(pn532, 0x05, cfg, sizeof(cfg));
}

bool pn532_set_passive_activation_retries(pn532_t *pn532, uint8_t max_retries)
{
    return pn532_set_max_retries(pn532, 0xFF, 0x01, max_retries);
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
    if (!pn532_execute_command(pn532, PN532_COMMAND_INRELEASE, params, sizeof(params), response, &response_len,
                               (uint16_t)pn532->timeout_ms)) {
        return false;
    }

    /* UM0701-02 §7.3.11: InRelease returns a status byte like InSelect and
     * InDeselect. Only 0x00 means the target was released; 0x27 means the
     * target number is not known. Per the NXP TAMA reference (its release
     * path ignores the status and always closes the session) a release after
     * the chip already lost the target is not an error the caller can act
     * on: treat 0x27 as "nothing left to release", clear the local state,
     * and succeed so poll loops keep working. Any other non-zero status is a
     * real error and leaves the state untouched. */
    if (response_len == 0) {
        ESP_LOGE(TAG, "pn532_release_target: empty response");
        return false;
    }
    if (response[0] == PN532_STATUS_TARGET_NOT_KNOWN) {
        ESP_LOGD(TAG, "pn532_release_target: target already lost (0x27)");
        pn532->inListedTag    = 0;
        pn532->session_opened = false;
        return true;
    }
    if (response[0] != PN532_STATUS_OK) {
        ESP_LOGE(TAG, "pn532_release_target: status 0x%02X", response[0]);
        return false;
    }

    pn532->inListedTag    = 0;
    pn532->session_opened = false;
    return true;
}

bool pn532_deselect_target(pn532_t *pn532)
{
    if (pn532 == NULL) {
        return false;
    }

    if (pn532->inListedTag == 0) {
        return true;
    }

    bool ok = pn532_in_deselect(pn532, pn532->inListedTag);
    if (ok) {
        /* Target stays listed for the chip; only our session flag drops. */
        pn532->session_opened = false;
    }
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

    uint8_t  raw_response[PN532_MAX_BUF_SIZE];
    uint8_t *raw_cursor        = response;
    size_t   raw_capacity      = (response != NULL && response_len != NULL) ? *response_len : 0;
    size_t   total_payload     = 0;
    bool     chaining_active   = true;
    bool     exchange_failed   = false;
    bool     capacity_exceeded = false;

    /* NXP phTalTama_Transceive(): a response status with MI (0x40) means the
     * target chains more information. The host re-issues the exchange to
     * drain the chain and concatenates the payload fragments in order; the
     * final round carries a status without MI. A chain that never terminates
     * is cut off after PN532_MI_MAX_CHAIN_ROUNDS rounds. */
    for (unsigned round = 0; chaining_active; round++) {
        if (round >= PN532_MI_MAX_CHAIN_ROUNDS) {
            ESP_LOGE(TAG, "pn532_in_data_exchange: MI chain did not terminate within %u rounds",
                     (unsigned)PN532_MI_MAX_CHAIN_ROUNDS);
            pn532->session_opened = false;
            if (response_len != NULL) {
                *response_len = total_payload;
            }
            return false;
        }

        size_t raw_response_len = sizeof(raw_response);
        if (!pn532_execute_command(pn532, PN532_COMMAND_INDATAEXCHANGE, params, data_len + 1, raw_response,
                                   &raw_response_len, timeout)) {
            exchange_failed = true;
            break;
        }
        if (raw_response_len == 0) {
            ESP_LOGE(TAG, "pn532_in_data_exchange: empty response");
            exchange_failed = true;
            break;
        }

        uint8_t status = raw_response[0] & PN532_STATUS_ERROR_MASK;
        if (status != PN532_STATUS_OK) {
            /*
             * NXP's TAMA stack reports 0x01/0x13/0x14 as RF timeout style errors
             * from transceive, but it does not discard the target handle there.
             * Keep the listed target number and only mark the session as needing
             * a fresh InSelect before the next exchange. Error codes live in the
             * low 6 bits (ERROR_MASK 0x3F); MI (0x40) and NAD (0x80) are data
             * flags, not errors.
             */
            if (pn532_status_requires_reselect(status)) {
                if (status == PN532_STATUS_RF_TIMEOUT) {
                    /* NXP's TAMA switches the field OFF after an RF_TIMEOUT to
                     * keep PN53x/PN51x state consistent; mirror that with a
                     * best-effort RFConfiguration (a failure here must not mask
                     * the RF_TIMEOUT the caller sees). Switching the field off
                     * makes the PN532 drop every listed target, so the stale
                     * target handle must not survive either — otherwise the
                     * next auto-InSelect hits 0x27 forever (the TAMA reference
                     * keeps its handle but treats 0x27 as success in its
                     * connect path, which we deliberately do not). */
                    pn532->is_rf_on               = false;
                    pn532->inListedTag            = 0;
                    const uint8_t rf_off_params[] = {0x01, 0x02};
                    size_t        rf_response_len = 0;
                    (void)pn532_execute_command(pn532, PN532_COMMAND_RFCONFIGURATION, rf_off_params,
                                                sizeof(rf_off_params), NULL, &rf_response_len,
                                                (uint16_t)pn532->timeout_ms);
                }
                pn532->session_opened = false;
            }
            ESP_LOGD(TAG, "pn532_in_data_exchange: PN532 status 0x%02X", status);
            exchange_failed = true;
            break;
        }

        const uint8_t *fragment    = raw_response + 1;
        size_t         payload_len = raw_response_len - 1;
        bool           nad_present = (raw_response[0] & PN532_STATUS_NAD_MASK) != 0;
        if (nad_present) {
            /* NXP phTalTama_Transceive(): when the status carries NAD (0x80)
             * the first payload byte is the node address, not card data. We
             * never negotiate NAD (no SetTamaParameters), but a target that
             * sends it anyway must not shift the caller's payload. */
            if (payload_len == 0) {
                ESP_LOGE(TAG, "pn532_in_data_exchange: NAD flag with empty payload");
                exchange_failed = true;
                break;
            }
            fragment++;
            payload_len--;
        }

        if (raw_cursor != NULL && payload_len > 0) {
            if (total_payload + payload_len > raw_capacity) {
                capacity_exceeded = true;
                total_payload += payload_len;
                break;
            }
            memcpy(raw_cursor, fragment, payload_len);
            raw_cursor += payload_len;
        }
        total_payload += payload_len;

        chaining_active = (raw_response[0] & PN532_STATUS_MI_MASK) != 0;
    }

    if (response_len != NULL) {
        *response_len = total_payload;
    }
    if (capacity_exceeded) {
        return false;
    }
    return !exchange_failed;
}

bool pn532_in_communicate_thru(pn532_t *pn532, const uint8_t *data, size_t data_len, uint8_t *response,
                               size_t *response_len, uint16_t timeout)
{
    if (pn532 == NULL || data == NULL || data_len == 0 || data_len + 1 > PN532_MAX_BUF_SIZE) {
        return false;
    }

    if (pn532->inListedTag == 0) {
        ESP_LOGE(TAG, "pn532_in_communicate_thru: no target selected");
        return false;
    }

    /* NXP phTalTama_Transceive() raw-command path: InCommunicateThru sends
     * raw ISO14443 bits to the target without the DEP/MIFARE wrapping of
     * InDataExchange. The response status byte uses the same ERROR_MASK /
     * MI layout, so MI-chained raw replies are drained here as well. */
    uint8_t  raw_response[PN532_MAX_BUF_SIZE];
    uint8_t *raw_cursor        = response;
    size_t   raw_capacity      = (response != NULL && response_len != NULL) ? *response_len : 0;
    size_t   total_payload     = 0;
    bool     chaining_active   = true;
    bool     exchange_failed   = false;
    bool     capacity_exceeded = false;

    for (unsigned round = 0; chaining_active; round++) {
        if (round >= PN532_MI_MAX_CHAIN_ROUNDS) {
            ESP_LOGE(TAG, "pn532_in_communicate_thru: MI chain did not terminate within %u rounds",
                     (unsigned)PN532_MI_MAX_CHAIN_ROUNDS);
            pn532->session_opened = false;
            if (response_len != NULL) {
                *response_len = total_payload;
            }
            return false;
        }

        size_t raw_response_len = sizeof(raw_response);
        if (!pn532_execute_command(pn532, PN532_COMMAND_INCOMMUNICATETHRU, data, data_len, raw_response,
                                   &raw_response_len, timeout)) {
            exchange_failed = true;
            break;
        }
        if (raw_response_len == 0) {
            ESP_LOGE(TAG, "pn532_in_communicate_thru: empty response");
            exchange_failed = true;
            break;
        }

        uint8_t status = raw_response[0] & PN532_STATUS_ERROR_MASK;
        if (status != PN532_STATUS_OK) {
            ESP_LOGD(TAG, "pn532_in_communicate_thru: PN532 status 0x%02X", status);
            exchange_failed = true;
            break;
        }

        const uint8_t *fragment    = raw_response + 1;
        size_t         payload_len = raw_response_len - 1;
        if ((raw_response[0] & PN532_STATUS_NAD_MASK) != 0) {
            /* Same NAD handling as pn532_in_data_exchange(); see there. */
            if (payload_len == 0) {
                ESP_LOGE(TAG, "pn532_in_communicate_thru: NAD flag with empty payload");
                exchange_failed = true;
                break;
            }
            fragment++;
            payload_len--;
        }

        if (raw_cursor != NULL && payload_len > 0) {
            if (total_payload + payload_len > raw_capacity) {
                capacity_exceeded = true;
                total_payload += payload_len;
                break;
            }
            memcpy(raw_cursor, fragment, payload_len);
            raw_cursor += payload_len;
        }
        total_payload += payload_len;

        chaining_active = (raw_response[0] & PN532_STATUS_MI_MASK) != 0;
    }

    if (response_len != NULL) {
        *response_len = total_payload;
    }
    if (capacity_exceeded) {
        return false;
    }
    return !exchange_failed;
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
    /* UM0701-02 §7.3.12: InSelect returns 0x00 on success; 0x27 means the
     * target number is not known to the PN532 and is a hard error, not an
     * idempotent "already selected" confirmation. */
    if (status[0] != PN532_STATUS_OK) {
        ESP_LOGE(TAG, "pn532_in_select: status 0x%02X", status[0]);
        pn532->session_opened = false;
        return false;
    }
    pn532->inListedTag    = target_number;
    pn532->session_opened = true;
    return true;
}

bool pn532_in_deselect(pn532_t *pn532, uint8_t target_number)
{
    const uint8_t params[]   = {target_number};
    uint8_t       status[1]  = {0};
    size_t        status_len = sizeof(status);
    if (!pn532_execute_command(pn532, PN532_COMMAND_INDESELECT, params, sizeof(params), status, &status_len,
                               (uint16_t)pn532->timeout_ms)) {
        pn532->session_opened = false;
        return false;
    }
    if (status_len == 0) {
        ESP_LOGE(TAG, "pn532_in_deselect: empty response");
        pn532->session_opened = false;
        return false;
    }
    /* UM0701-02 §7.3.10: InDeselect returns 0x00 on success; 0x27 means the
     * target is not attributed anymore. Like the NXP TAMA reference (which
     * closes the session on both 0x00 and 0x27), a target the chip already
     * lost is deselected as far as we are concerned. Unlike the 0x00 path —
     * where the chip keeps the target listed for reactivation — 0x27 means
     * the handle is gone on the chip side too, so our inListedTag must not
     * survive; a stale handle would make every later auto-InSelect fail
     * with 0x27 (our InSelect, unlike TAL's connect, treats it as an
     * error). Other non-zero statuses are errors. */
    if (status[0] == PN532_STATUS_TARGET_NOT_KNOWN) {
        ESP_LOGD(TAG, "pn532_in_deselect: target already lost (0x27)");
        pn532->inListedTag    = 0;
        pn532->session_opened = false;
        return true;
    }
    if (status[0] != PN532_STATUS_OK) {
        ESP_LOGE(TAG, "pn532_in_deselect: status 0x%02X", status[0]);
        pn532->session_opened = false;
        return false;
    }
    pn532->session_opened = false;
    return true;
}

bool pn532_recover(pn532_t *pn532)
{
    if (pn532 == NULL) {
        return false;
    }

    /* Full software re-initialisation without tearing down the transport:
     * abort anything in flight, drop target/session state, verify the link
     * (re-negotiating it if the chip went silent), re-apply the SAM/retry
     * runtime configuration, and leave the RF field off. */
    pn532_abort_current_command(pn532);
    pn532_reset(pn532);

    if (pn532_get_firmware_version(pn532) == 0 && !pn532_resync_link(pn532)) {
        ESP_LOGE(TAG, "pn532_recover: device does not answer");
        return false;
    }

    if (!pn532_restore_runtime_config(pn532)) {
        return false;
    }

    if (!pn532_set_rf_off(pn532)) {
        return false;
    }

    return true;
}
