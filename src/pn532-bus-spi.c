#include "pn532-internal.h"

#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "PN532-SPI";

typedef struct
{
    pn532_bus_t         base;
    spi_device_handle_t spi_handle;
    gpio_num_t          nss;
    spi_transaction_t  *trans;
    uint8_t            *tx_buffer;
    uint8_t            *rx_buffer;
} pn532_spi_bus_t;

static pn532_spi_bus_t *pn532_spi_bus(pn532_bus_t *bus)
{
    return (pn532_spi_bus_t *)bus;
}

static void pn532_spi_pre_transfer(spi_transaction_t *trans)
{
    pn532_spi_bus_t *bus = (pn532_spi_bus_t *)trans->user;
    if (bus != NULL) {
        gpio_set_level(bus->nss, 0);
        esp_rom_delay_us(100);
    }
}

static void pn532_spi_post_transfer(spi_transaction_t *trans)
{
    pn532_spi_bus_t *bus = (pn532_spi_bus_t *)trans->user;
    if (bus != NULL) {
        gpio_set_level(bus->nss, 1);
    }
}

static bool pn532_spi_bus_write_command(pn532_bus_t *bus, const uint8_t *buffer, size_t len)
{
    pn532_spi_bus_t *spi_bus = pn532_spi_bus(bus);

    if (spi_bus == NULL || buffer == NULL || len == 0 || len > PN532_MAX_BUF_SIZE) {
        return false;
    }

    if (buffer[0] == 0x00 && len > 1) {
        buffer++;
        len--;
    }

    spi_bus->tx_buffer[0] = 0x00;
    memcpy(spi_bus->tx_buffer + 1, buffer, len);
    spi_bus->tx_buffer[len + 1u] = 0x00;

    memset(spi_bus->trans, 0, sizeof(*spi_bus->trans));
    spi_bus->trans->cmd       = PN532_SPI_DATAWRITE;
    spi_bus->trans->length    = (len + 2u) * 8u;
    spi_bus->trans->tx_buffer = spi_bus->tx_buffer;
    spi_bus->trans->user      = spi_bus;

    esp_err_t err = spi_device_transmit(spi_bus->spi_handle, spi_bus->trans);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_spi_bus_write_command: failed (%s)", esp_err_to_name(err));
        return false;
    }
    return true;
}

static bool pn532_spi_bus_read_data(pn532_bus_t *bus, uint8_t *buffer, size_t len)
{
    pn532_spi_bus_t *spi_bus = pn532_spi_bus(bus);

    if (spi_bus == NULL || buffer == NULL || len == 0 || len > PN532_MAX_BUF_SIZE) {
        return false;
    }

    memset(spi_bus->trans, 0, sizeof(*spi_bus->trans));
    spi_bus->trans->cmd       = PN532_SPI_DATAREAD;
    spi_bus->trans->rxlength  = len * 8u;
    spi_bus->trans->rx_buffer = spi_bus->rx_buffer;
    spi_bus->trans->user      = spi_bus;

    esp_err_t err = spi_device_transmit(spi_bus->spi_handle, spi_bus->trans);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_spi_bus_read_data: data failed (%s)", esp_err_to_name(err));
        return false;
    }

    memcpy(buffer, spi_bus->rx_buffer, len);
    return true;
}

static bool pn532_spi_bus_is_ready(pn532_bus_t *bus)
{
    pn532_spi_bus_t *spi_bus = pn532_spi_bus(bus);

    if (spi_bus == NULL) {
        return false;
    }

    memset(spi_bus->trans, 0, sizeof(*spi_bus->trans));
    spi_bus->trans->cmd         = PN532_SPI_STATREAD;
    spi_bus->trans->rxlength    = 8;
    spi_bus->trans->flags       = SPI_TRANS_USE_RXDATA;
    spi_bus->trans->user        = spi_bus;

    esp_err_t err = spi_device_transmit(spi_bus->spi_handle, spi_bus->trans);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_spi_bus_is_ready: failed (%s)", esp_err_to_name(err));
        return false;
    }

    return (spi_bus->trans->rx_data[0] & PN532_SPI_READY) == PN532_SPI_READY;
}

static void pn532_spi_bus_wake(pn532_bus_t *bus)
{
    pn532_spi_bus_t *spi_bus = pn532_spi_bus(bus);

    if (spi_bus == NULL) {
        return;
    }
    /*
     * PN532/C1 §8.5.6 wake-up: NSS high → low edge with T1 (max 2 ms) settle
     * before any SPI traffic. Do NOT send a host→PN532 ACK here — that would
     * abort the very next command (e.g. GetFirmwareVersion in init).
     */
    gpio_set_level(spi_bus->nss, 1);
    vTaskDelay(pdMS_TO_TICKS(2));
    gpio_set_level(spi_bus->nss, 0);
    vTaskDelay(pdMS_TO_TICKS(2));
    gpio_set_level(spi_bus->nss, 1);
}

static void pn532_spi_bus_destroy(pn532_bus_t *bus)
{
    pn532_spi_bus_t *spi_bus = pn532_spi_bus(bus);

    if (spi_bus != NULL) {
        if (spi_bus->spi_handle != NULL) {
            esp_err_t err = spi_bus_remove_device(spi_bus->spi_handle);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "pn532_spi_bus_destroy: spi_bus_remove_device failed (%s)", esp_err_to_name(err));
            }
        }
        free(spi_bus->trans);
        free(spi_bus->tx_buffer);
        free(spi_bus->rx_buffer);
    }

    free(spi_bus);
}

static bool pn532_spi_bus_init(spi_host_device_t host_id, gpio_num_t sck, gpio_num_t miso, gpio_num_t mosi)
{
    spi_bus_config_t bus_config = {
        .mosi_io_num = mosi,
        .miso_io_num = miso,
        .sclk_io_num = sck,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .data4_io_num = -1,
        .data5_io_num = -1,
        .data6_io_num = -1,
        .data7_io_num = -1,
        .max_transfer_sz = PN532_MAX_BUF_SIZE + 2,
    };

    esp_err_t err = spi_bus_initialize(host_id, &bus_config, SPI_DMA_CH_AUTO);
    if (err == ESP_ERR_INVALID_STATE) {
        return true;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_spi_bus_init: spi_bus_initialize failed (%s)", esp_err_to_name(err));
        return false;
    }
    return true;
}

static pn532_bus_t *pn532_spi_attach(spi_host_device_t host_id, gpio_num_t nss, int clock_speed_hz)
{
    pn532_spi_bus_t *spi_bus = calloc(1, sizeof(*spi_bus));
    if (spi_bus == NULL) {
        return NULL;
    }

    /*
     * PN532 SPI wake-up: idle NSS high, then drive low to trigger the SPI
     * wake-up source (PN532/C1 §8.5.6). Wait T1 = 2 ms max for the CPU clock
     * to start before any SPI traffic. NSS stays low into the first
     * transaction, which then drives CS itself.
     */
    gpio_config_t nss_cfg = {
        .pin_bit_mask = (1ULL << nss),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    if (gpio_config(&nss_cfg) != ESP_OK) {
        free(spi_bus);
        return NULL;
    }
    gpio_set_level(nss, 1);
    vTaskDelay(pdMS_TO_TICKS(2));
    gpio_set_level(nss, 0);
    vTaskDelay(pdMS_TO_TICKS(2));

    spi_device_interface_config_t dev_config = {
        .command_bits   = 8,
        .clock_speed_hz = clock_speed_hz,
        .mode           = 0,
        .spics_io_num   = -1,
        .queue_size     = 3,
        .flags          = SPI_DEVICE_HALFDUPLEX | SPI_DEVICE_BIT_LSBFIRST,
        .pre_cb         = pn532_spi_pre_transfer,
        .post_cb        = pn532_spi_post_transfer,
    };

    if (spi_bus_add_device(host_id, &dev_config, &spi_bus->spi_handle) != ESP_OK) {
        free(spi_bus);
        ESP_LOGE(TAG, "pn532_spi_attach: failed to add SPI device");
        return NULL;
    }

    spi_bus->trans     = heap_caps_malloc(sizeof(*spi_bus->trans), MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    spi_bus->tx_buffer = spi_bus_dma_memory_alloc(host_id, PN532_MAX_BUF_SIZE + 2, 0);
    spi_bus->rx_buffer = spi_bus_dma_memory_alloc(host_id, PN532_MAX_BUF_SIZE + 2, 0);
    if (spi_bus->trans == NULL || spi_bus->tx_buffer == NULL || spi_bus->rx_buffer == NULL) {
        spi_bus_remove_device(spi_bus->spi_handle);
        free(spi_bus->trans);
        free(spi_bus->tx_buffer);
        free(spi_bus->rx_buffer);
        free(spi_bus);
        ESP_LOGE(TAG, "pn532_spi_attach: failed to allocate SPI scratch buffers");
        return NULL;
    }

    spi_bus->nss = nss;

    spi_bus->base.write_command = pn532_spi_bus_write_command;
    spi_bus->base.read_data     = pn532_spi_bus_read_data;
    spi_bus->base.is_ready      = pn532_spi_bus_is_ready;
    spi_bus->base.wake          = pn532_spi_bus_wake;
    spi_bus->base.destroy       = pn532_spi_bus_destroy;

    return &spi_bus->base;
}

pn532_bus_t *pn532_spi_init(spi_host_device_t host_id, gpio_num_t sck, gpio_num_t miso, gpio_num_t mosi, gpio_num_t nss, int clock_speed_hz)
{
    if (!pn532_spi_bus_init(host_id, sck, miso, mosi)) {
        return NULL;
    }
    return pn532_spi_attach(host_id, nss, clock_speed_hz);
}
