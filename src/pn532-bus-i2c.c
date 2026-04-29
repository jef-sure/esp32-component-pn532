#include "pn532-internal.h"

#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "PN532-I2C";

#define PN532_I2C_READY                0x01
#define PN532_I2C_TRANSFER_TIMEOUT_MS  100
#define PN532_I2C_READY_RETRY_COUNT    8
#define PN532_I2C_READY_RETRY_DELAY_MS 5

typedef struct
{
    pn532_bus_t             base;
    i2c_master_bus_handle_t bus_handle;
    i2c_master_dev_handle_t dev_handle;
    uint8_t                *buffer;
} pn532_i2c_bus_t;

static pn532_i2c_bus_t *pn532_i2c_bus(pn532_bus_t *bus)
{
    return (pn532_i2c_bus_t *)bus;
}

static bool pn532_i2c_bus_write_command(pn532_bus_t *bus, const uint8_t *buffer, size_t len)
{
    pn532_i2c_bus_t *i2c_bus = pn532_i2c_bus(bus);

    if (i2c_bus == NULL || buffer == NULL || len == 0 || len > PN532_MAX_BUF_SIZE) {
        return false;
    }

    esp_err_t err = i2c_master_transmit(i2c_bus->dev_handle, buffer, len, PN532_I2C_TRANSFER_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_i2c_bus_write_command: i2c_master_transmit failed (%s)", esp_err_to_name(err));
        return false;
    }

    return true;
}

static bool pn532_i2c_bus_read_data(pn532_bus_t *bus, uint8_t *buffer, size_t len)
{
    pn532_i2c_bus_t *i2c_bus = pn532_i2c_bus(bus);

    if (i2c_bus == NULL || i2c_bus->buffer == NULL || buffer == NULL || len == 0 || len > PN532_MAX_BUF_SIZE) {
        return false;
    }

    for (int attempt = 0; attempt < PN532_I2C_READY_RETRY_COUNT; attempt++) {
        esp_err_t err =
            i2c_master_receive(i2c_bus->dev_handle, i2c_bus->buffer, len + 1, PN532_I2C_TRANSFER_TIMEOUT_MS);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "pn532_i2c_bus_read_data: i2c_master_receive failed (%s)", esp_err_to_name(err));
            return false;
        }

        if (i2c_bus->buffer[0] == PN532_I2C_READY) {
            memcpy(buffer, i2c_bus->buffer + 1, len);
            return true;
        }

        vTaskDelay(pdMS_TO_TICKS(PN532_I2C_READY_RETRY_DELAY_MS));
    }

    ESP_LOGE(TAG, "pn532_i2c_bus_read_data: device not ready after %d retries", PN532_I2C_READY_RETRY_COUNT);
    return false;
}

static bool pn532_i2c_bus_is_ready(pn532_bus_t *bus)
{
    pn532_i2c_bus_t *i2c_bus = pn532_i2c_bus(bus);
    uint8_t          status  = 0;

    if (i2c_bus == NULL) {
        return false;
    }

    esp_err_t err = i2c_master_receive(i2c_bus->dev_handle, &status, 1, PN532_I2C_TRANSFER_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_i2c_bus_is_ready: i2c_master_receive failed (%s)", esp_err_to_name(err));
        return false;
    }

    return status == PN532_I2C_READY;
}

static void pn532_i2c_bus_destroy(pn532_bus_t *bus)
{
    pn532_i2c_bus_t *i2c_bus = pn532_i2c_bus(bus);

    if (i2c_bus != NULL) {
        if (i2c_bus->dev_handle != NULL) {
            esp_err_t err = i2c_master_bus_rm_device(i2c_bus->dev_handle);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "pn532_i2c_bus_destroy: i2c_master_bus_rm_device failed (%s)", esp_err_to_name(err));
            }
        }

        if (i2c_bus->bus_handle != NULL) {
            esp_err_t err = i2c_del_master_bus(i2c_bus->bus_handle);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "pn532_i2c_bus_destroy: i2c_del_master_bus failed (%s)", esp_err_to_name(err));
            }
        }

        free(i2c_bus->buffer);
    }

    free(i2c_bus);
}

pn532_bus_t *pn532_i2c_init(i2c_port_num_t port, gpio_num_t scl, gpio_num_t sda, uint16_t device_address,
                            uint32_t clock_speed_hz)
{
    pn532_i2c_bus_t *i2c_bus = calloc(1, sizeof(*i2c_bus));
    if (i2c_bus == NULL) {
        return NULL;
    }

    i2c_bus->buffer = calloc(PN532_MAX_BUF_SIZE + 1, sizeof(uint8_t));
    if (i2c_bus->buffer == NULL) {
        free(i2c_bus);
        return NULL;
    }

    if (device_address == 0) {
        device_address = PN532_I2C_DEFAULT_ADDRESS;
    }

    i2c_master_bus_config_t bus_config = {
        .i2c_port                     = port,
        .sda_io_num                   = sda,
        .scl_io_num                   = scl,
        .clk_source                   = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt            = 7,
        .intr_priority                = 0,
        .trans_queue_depth            = 1,
        .flags.enable_internal_pullup = 1,
    };
    i2c_device_config_t dev_config = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = device_address,
        .scl_speed_hz    = clock_speed_hz,
        .scl_wait_us     = 0,
    };

    esp_err_t err = i2c_new_master_bus(&bus_config, &i2c_bus->bus_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_i2c_init: i2c_new_master_bus failed (%s)", esp_err_to_name(err));
        free(i2c_bus->buffer);
        free(i2c_bus);
        return NULL;
    }

    err = i2c_master_bus_add_device(i2c_bus->bus_handle, &dev_config, &i2c_bus->dev_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_i2c_init: i2c_master_bus_add_device failed (%s)", esp_err_to_name(err));
        i2c_del_master_bus(i2c_bus->bus_handle);
        free(i2c_bus->buffer);
        free(i2c_bus);
        return NULL;
    }

    i2c_bus->base.write_command = pn532_i2c_bus_write_command;
    i2c_bus->base.read_data     = pn532_i2c_bus_read_data;
    i2c_bus->base.is_ready      = pn532_i2c_bus_is_ready;
    i2c_bus->base.destroy       = pn532_i2c_bus_destroy;
    return &i2c_bus->base;
}