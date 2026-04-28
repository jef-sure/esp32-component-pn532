#include "pn532-internal.h"

#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "PN532-UART";

#define PN532_ACK_FRAME_LEN 6
#define PN532_UART_IO_TIMEOUT_MS 100
#define PN532_UART_READ_IDLE_MS 20
#define PN532_UART_RX_BUFFER_SIZE (PN532_MAX_BUF_SIZE * 2)

typedef struct
{
    pn532_bus_t base;
    uart_port_t uart_num;
} pn532_uart_bus_t;

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

static bool pn532_uart_bus_read_data(pn532_bus_t *bus, uint8_t *buffer, size_t len)
{
    pn532_uart_bus_t *uart_bus = pn532_uart_bus(bus);
    size_t total = 0;

    if (uart_bus == NULL || buffer == NULL || len == 0) {
        return false;
    }

    memset(buffer, 0, len);

    while (total < len) {
        int read = uart_read_bytes(uart_bus->uart_num, buffer + total, len - total, pdMS_TO_TICKS(PN532_UART_READ_IDLE_MS));
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
    pn532_uart_bus_t *uart_bus = pn532_uart_bus(bus);
    size_t buffered_len = 0;

    if (uart_bus == NULL) {
        return false;
    }

    esp_err_t err = uart_get_buffered_data_len(uart_bus->uart_num, &buffered_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_uart_bus_is_ready: uart_get_buffered_data_len failed (%s)", esp_err_to_name(err));
        return false;
    }

    return buffered_len > 0;
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
        .baud_rate = (baud_rate > 0) ? baud_rate : PN532_UART_DEFAULT_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk = UART_SCLK_DEFAULT,
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

    /*
     * HSU wake-up: PN532 enters low-power state on power-up and after PowerDown.
     * Per NXP UM0701-02 §6.2.1, host must send a wake-up preamble (0x55 byte
     * followed by at least 15 ms of dummy bytes) before the first command is
     * accepted. We send a generous burst followed by a small idle delay so the
     * subsequent SAMConfiguration call from pn532_init() is recognised.
     */
    static const uint8_t pn532_uart_wakeup[] = {
        0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    int written = uart_write_bytes(uart_num, pn532_uart_wakeup, sizeof(pn532_uart_wakeup));
    if (written != (int)sizeof(pn532_uart_wakeup)) {
        ESP_LOGW(TAG, "pn532_uart_init: failed to send HSU wake-up preamble");
    }
    (void)uart_wait_tx_done(uart_num, pdMS_TO_TICKS(PN532_UART_IO_TIMEOUT_MS));
    vTaskDelay(pdMS_TO_TICKS(20));
    (void)uart_flush_input(uart_num);

    uart_bus->uart_num = uart_num;

    uart_bus->base.write_command = pn532_uart_bus_write_command;
    uart_bus->base.read_data = pn532_uart_bus_read_data;
    uart_bus->base.is_ready = pn532_uart_bus_is_ready;
    uart_bus->base.destroy = pn532_uart_bus_destroy;
    return &uart_bus->base;
}