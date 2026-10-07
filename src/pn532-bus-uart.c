#include "pn532-internal.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "PN532-UART";

#define PN532_ACK_FRAME_LEN        6
#define PN532_UART_MIN_READY_BYTES PN532_ACK_FRAME_LEN
#define PN532_UART_IO_TIMEOUT_MS   100
#define PN532_UART_READ_IDLE_MS    20
#define PN532_UART_RX_BUFFER_SIZE  (PN532_MAX_BUF_SIZE * 2)
#define PN532_UART_SHORT_HEADER    5 /* 00 00 FF LEN LCS */
#define PN532_UART_EXT_HEADER      8 /* 00 00 FF FF FF LENM LENL LCS */

typedef struct
{
    pn532_bus_t base;
    uart_port_t uart_num;
    uint32_t    baud_rate;
} pn532_uart_bus_t;

/* UM0701-02 §7.2.8 SetSerialBaudRate BR codes; looked up by rate, never by index. */
static const struct
{
    uint32_t hz;
    uint8_t  pn532_code;
} pn532_hsu_bauds[] = {
    {9600, 0x00},   {19200, 0x01},  {38400, 0x02},  {57600, 0x03},   {115200, 0x04},
    {230400, 0x05}, {460800, 0x06}, {921600, 0x07}, {1288000, 0x08},
};

static pn532_uart_bus_t *pn532_uart_bus(pn532_bus_t *bus)
{
    return (pn532_uart_bus_t *)bus;
}

static bool pn532_uart_bus_write_command(pn532_bus_t *bus, const uint8_t *buffer, size_t len)
{
    pn532_uart_bus_t *uart_bus = pn532_uart_bus(bus);

    if (uart_bus == NULL || buffer == NULL || len == 0) {
        return false;
    }

    esp_err_t err = uart_flush_input(uart_bus->uart_num);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "pn532_uart_bus_write_command: uart_flush_input failed (%s)", esp_err_to_name(err));
    }

    int written = uart_write_bytes(uart_bus->uart_num, buffer, len);
    if (written < 0 || (size_t)written != len) {
        ESP_LOGE(TAG, "pn532_uart_bus_write_command: uart_write_bytes failed");
        return false;
    }

    err = uart_wait_tx_done(uart_bus->uart_num, pdMS_TO_TICKS(PN532_UART_IO_TIMEOUT_MS));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_uart_bus_write_command: uart_wait_tx_done failed (%s)", esp_err_to_name(err));
        return false;
    }

    return true;
}

typedef enum
{
    PN532_UART_FRAME_OK,
    PN532_UART_FRAME_BAD_HEADER, /* fall back to the idle heuristic */
    PN532_UART_FRAME_TIMEOUT,
} pn532_uart_frame_result_t;

/* Read len bytes until the deadline; *total grows by the bytes actually read. */
static bool pn532_uart_read_until(pn532_uart_bus_t *uart_bus, uint8_t *buffer, size_t len, TickType_t deadline,
                                  size_t *total)
{
    int32_t remaining = (int32_t)(deadline - xTaskGetTickCount());
    int     read      = uart_read_bytes(uart_bus->uart_num, buffer, len, remaining > 0 ? (TickType_t)remaining : 0);
    if (read > 0) {
        *total += (size_t)read;
    }
    return read >= 0 && (size_t)read == len;
}

/*
 * Response read driven by the frame header: 5 header bytes (8 for an extended
 * frame), then exactly LEN + 2 bytes (TFI + PD = LEN, plus DCS and postamble).
 * One time budget, sized for a full frame at the current baud, covers all
 * phases. *total reports the bytes stored in buffer in every outcome.
 */
static pn532_uart_frame_result_t pn532_uart_read_framed(pn532_uart_bus_t *uart_bus, uint8_t *buffer, size_t cap,
                                                        size_t *total)
{
    uint32_t   baud      = uart_bus->baud_rate > 0 ? uart_bus->baud_rate : PN532_UART_DEFAULT_BAUD_RATE;
    uint32_t   budget_ms = PN532_UART_IO_TIMEOUT_MS + (uint32_t)((PN532_MAX_BUF_SIZE * 10ULL * 1000ULL) / baud);
    TickType_t deadline  = xTaskGetTickCount() + pdMS_TO_TICKS(budget_ms);

    *total = 0;
    if (!pn532_uart_read_until(uart_bus, buffer, PN532_UART_SHORT_HEADER, deadline, total)) {
        return PN532_UART_FRAME_BAD_HEADER;
    }
    if (buffer[0] != PN532_PREAMBLE || buffer[1] != PN532_STARTCODE1 || buffer[2] != PN532_STARTCODE2) {
        return PN532_UART_FRAME_BAD_HEADER;
    }

    size_t header_len;
    size_t frame_len;
    if (buffer[3] == 0xFF && buffer[4] == 0xFF) {
        if (!pn532_uart_read_until(uart_bus, buffer + *total, PN532_UART_EXT_HEADER - *total, deadline, total) ||
            (uint8_t)(buffer[5] + buffer[6] + buffer[7]) != 0) {
            return PN532_UART_FRAME_BAD_HEADER;
        }
        header_len = PN532_UART_EXT_HEADER;
        frame_len  = ((size_t)buffer[5] << 8) | buffer[6];
    } else {
        if ((uint8_t)(buffer[3] + buffer[4]) != 0) {
            return PN532_UART_FRAME_BAD_HEADER;
        }
        header_len = PN532_UART_SHORT_HEADER;
        frame_len  = buffer[3];
    }

    size_t frame_total = header_len + frame_len + 2;
    if (frame_total > cap) {
        return PN532_UART_FRAME_BAD_HEADER;
    }
    if (!pn532_uart_read_until(uart_bus, buffer + header_len, frame_total - header_len, deadline, total)) {
        ESP_LOGE(TAG, "pn532_uart_bus_read_data: frame body timed out (%u/%u bytes)", (unsigned int)*total,
                 (unsigned int)frame_total);
        return PN532_UART_FRAME_TIMEOUT;
    }
    return PN532_UART_FRAME_OK;
}

static bool pn532_uart_bus_read_data(pn532_bus_t *bus, uint8_t *buffer, size_t len)
{
    pn532_uart_bus_t *uart_bus = pn532_uart_bus(bus);
    size_t            total    = 0;

    if (uart_bus == NULL || buffer == NULL || len == 0) {
        return false;
    }

    memset(buffer, 0, len);

    if (len == PN532_MAX_BUF_SIZE) {
        switch (pn532_uart_read_framed(uart_bus, buffer, len, &total)) {
        case PN532_UART_FRAME_OK:
            return true;
        case PN532_UART_FRAME_TIMEOUT:
            return false;
        case PN532_UART_FRAME_BAD_HEADER:
            if (total > 0) {
                ESP_LOGW(TAG, "pn532_uart_bus_read_data: unexpected frame header, falling back to idle read");
            }
            break;
        }
    }

    while (total < len) {
        int read =
            uart_read_bytes(uart_bus->uart_num, buffer + total, len - total, pdMS_TO_TICKS(PN532_UART_READ_IDLE_MS));
        if (read < 0) {
            ESP_LOGE(TAG, "pn532_uart_bus_read_data: uart_read_bytes failed");
            return false;
        }

        if (read == 0) {
            if (total == 0) {
                return false;
            }
            if (len != PN532_MAX_BUF_SIZE && total < len) {
                return false;
            }
            break;
        }

        total += (size_t)read;
        if (len == PN532_ACK_FRAME_LEN && total == len) {
            break;
        }
    }

    if (len != PN532_MAX_BUF_SIZE && total != len) {
        ESP_LOGE(TAG, "pn532_uart_bus_read_data: short read (%u/%u)", (unsigned int)total, (unsigned int)len);
        return false;
    }

    return total > 0;
}

static bool pn532_uart_bus_is_ready(pn532_bus_t *bus)
{
    pn532_uart_bus_t *uart_bus     = pn532_uart_bus(bus);
    size_t            buffered_len = 0;

    if (uart_bus == NULL) {
        return false;
    }

    esp_err_t err = uart_get_buffered_data_len(uart_bus->uart_num, &buffered_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_uart_bus_is_ready: uart_get_buffered_data_len failed (%s)", esp_err_to_name(err));
        return false;
    }

    return buffered_len >= PN532_UART_MIN_READY_BYTES;
}

static void pn532_uart_bus_wake(pn532_bus_t *bus)
{
    pn532_uart_bus_t *uart_bus = pn532_uart_bus(bus);

    if (uart_bus == NULL) {
        return;
    }

    /*
     * HSU wake-up, mirroring NXP phTalTama_WakeUp: the PN532 enters low-power
     * state on power-up and after PowerDown. Per UM0701-02 §7.2.11 the host
     * sends 0x55 0x55 followed by dummy zeros before the first command is
     * accepted. Called from pn532_reset()/pn532_recover() so a sleeping chip
     * is also woken on recovery, not only at bus creation.
     */
    static const uint8_t wakeup[] = {0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int                  written  = uart_write_bytes(uart_bus->uart_num, wakeup, sizeof(wakeup));
    if (written != (int)sizeof(wakeup)) {
        ESP_LOGW(TAG, "pn532_uart_bus_wake: failed to send HSU wake-up preamble");
    }
    (void)uart_wait_tx_done(uart_bus->uart_num, pdMS_TO_TICKS(PN532_UART_IO_TIMEOUT_MS));
    vTaskDelay(pdMS_TO_TICKS(20));
    (void)uart_flush_input(uart_bus->uart_num);
}

static bool pn532_uart_bus_set_baud(pn532_uart_bus_t *uart_bus, uint32_t baud_rate)
{
    (void)uart_wait_tx_done(uart_bus->uart_num, pdMS_TO_TICKS(PN532_UART_IO_TIMEOUT_MS));
    esp_err_t err = uart_set_baudrate(uart_bus->uart_num, baud_rate);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_uart_bus_set_baud: uart_set_baudrate(%" PRIu32 ") failed (%s)", baud_rate,
                 esp_err_to_name(err));
        return false;
    }
    uart_bus->baud_rate = baud_rate;
    /* Bytes received around the switch are garbage at either rate. */
    (void)uart_flush_input(uart_bus->uart_num);
    return true;
}

/* Configured rate failed: try every other HSU rate once, restore it if none answers. */
static bool pn532_uart_bus_resync(pn532_bus_t *bus, pn532_bus_probe_t probe, void *ctx)
{
    pn532_uart_bus_t *uart_bus   = pn532_uart_bus(bus);
    uint32_t          configured = uart_bus->baud_rate;

    for (size_t i = 0; i < sizeof(pn532_hsu_bauds) / sizeof(pn532_hsu_bauds[0]); i++) {
        uint32_t hz = pn532_hsu_bauds[i].hz;
        if (hz == configured || !pn532_uart_bus_set_baud(uart_bus, hz)) {
            continue;
        }
        pn532_uart_bus_wake(bus);
        if (probe(ctx)) {
            ESP_LOGW(TAG, "module answers at %" PRIu32 " baud, not the configured %" PRIu32 " baud", hz, configured);
            return true;
        }
    }

    (void)pn532_uart_bus_set_baud(uart_bus, configured);
    ESP_LOGE(TAG,
             "no answer at configured %" PRIu32
             " baud nor at 9600/19200/38400/57600/115200/230400/460800/921600/1288000",
             configured);
    return false;
}

static void pn532_uart_bus_destroy(pn532_bus_t *bus)
{
    pn532_uart_bus_t *uart_bus = pn532_uart_bus(bus);

    if (uart_bus != NULL) {
        if (uart_is_driver_installed(uart_bus->uart_num)) {
            esp_err_t err = uart_driver_delete(uart_bus->uart_num);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "pn532_uart_bus_destroy: uart_driver_delete failed (%s)", esp_err_to_name(err));
            }
        }
    }

    free(uart_bus);
}

pn532_bus_t *pn532_uart_init(uart_port_t uart_num, gpio_num_t tx, gpio_num_t rx, int baud_rate)
{
    pn532_uart_bus_t *uart_bus = calloc(1, sizeof(*uart_bus));
    if (uart_bus == NULL) {
        return NULL;
    }

    if (uart_is_driver_installed(uart_num)) {
        ESP_LOGE(TAG, "pn532_uart_init: UART driver is already installed on port %d", uart_num);
        free(uart_bus);
        return NULL;
    }

    uart_config_t config = {
        .baud_rate           = (baud_rate > 0) ? baud_rate : PN532_UART_DEFAULT_BAUD_RATE,
        .data_bits           = UART_DATA_8_BITS,
        .parity              = UART_PARITY_DISABLE,
        .stop_bits           = UART_STOP_BITS_1,
        .flow_ctrl           = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk          = UART_SCLK_DEFAULT,
    };

    esp_err_t err = uart_driver_install(uart_num, PN532_UART_RX_BUFFER_SIZE, 0, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_uart_init: uart_driver_install failed (%s)", esp_err_to_name(err));
        free(uart_bus);
        return NULL;
    }

    err = uart_param_config(uart_num, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_uart_init: uart_param_config failed (%s)", esp_err_to_name(err));
        uart_driver_delete(uart_num);
        free(uart_bus);
        return NULL;
    }

    err = uart_set_pin(uart_num, tx, rx, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_uart_init: uart_set_pin failed (%s)", esp_err_to_name(err));
        uart_driver_delete(uart_num);
        free(uart_bus);
        return NULL;
    }

    err = uart_flush_input(uart_num);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "pn532_uart_init: uart_flush_input failed (%s)", esp_err_to_name(err));
    }

    uart_bus->uart_num  = uart_num;
    uart_bus->baud_rate = (uint32_t)config.baud_rate;

    uart_bus->base.write_command = pn532_uart_bus_write_command;
    uart_bus->base.read_data     = pn532_uart_bus_read_data;
    uart_bus->base.is_ready      = pn532_uart_bus_is_ready;
    uart_bus->base.wake          = pn532_uart_bus_wake;
    uart_bus->base.destroy       = pn532_uart_bus_destroy;
    uart_bus->base.resync        = pn532_uart_bus_resync;

    /* Wake the chip once here; pn532_reset()/pn532_recover() re-send the same
     * preamble through base.wake when needed. */
    pn532_uart_bus_wake(&uart_bus->base);
    return &uart_bus->base;
}

/* Response timeout of SetSerialBaudRate when the device has none configured. */
#define PN532_UART_BAUD_CHANGE_TIMEOUT_MS 500

bool pn532_uart_set_baud_rate(pn532_t *pn532, uint32_t baud_rate)
{
    static const uint8_t ack[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};

    if (pn532 == NULL || pn532->bus == NULL || pn532->bus->destroy != pn532_uart_bus_destroy) {
        return false;
    }

    const uint8_t *code = NULL;
    for (size_t i = 0; i < sizeof(pn532_hsu_bauds) / sizeof(pn532_hsu_bauds[0]); i++) {
        if (pn532_hsu_bauds[i].hz == baud_rate) {
            code = &pn532_hsu_bauds[i].pn532_code;
            break;
        }
    }
    if (code == NULL) {
        ESP_LOGE(TAG, "pn532_uart_set_baud_rate: unsupported rate %" PRIu32, baud_rate);
        return false;
    }

    /* A zero timeout means "wait without limit" to pn532_execute_command();
     * this command is answered at once, so it never needs that. */
    uint16_t timeout = pn532->timeout_ms != 0 ? pn532->timeout_ms : PN532_UART_BAUD_CHANGE_TIMEOUT_MS;
    if (!pn532_execute_command(pn532, PN532_COMMAND_SETSERIALBAUDRATE, code, 1, NULL, NULL, timeout)) {
        /* The PN532 switches when it gets a host ACK after its response
         * (UM0701-02 §7.2.8, fig. 53). If the response was sent but lost on
         * the line, the ACK of the abort procedure is that ACK: the module
         * may be on the new rate although the command failed here. */
        ESP_LOGW(TAG, "pn532_uart_set_baud_rate: command failed, the module may be on either rate");
        return false;
    }

    /* UM0701-02 §7.2.8: the ACK is mandatory here; the PN532 switches only after
     * it, and the next command must wait at least 200 us. */
    if (!pn532_uart_bus_write_command(pn532->bus, ack, sizeof(ack))) {
        return false;
    }
    pn532_delay_ms(2);
    return pn532_uart_bus_set_baud(pn532_uart_bus(pn532->bus), baud_rate);
}