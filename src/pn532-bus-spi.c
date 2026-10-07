#include "pn532-internal.h"

#include <stdlib.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_attr.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/gpio_ll.h"

static const char *TAG = "PN532-SPI";

/* PN532/C1 §8.5.6: after the NSS falling edge the oscillator needs T_osc_start
 * (T1, up to 2 ms with the usual quartz) before the chip takes SPI traffic.
 * The pulse is held longer than that maximum to leave a margin. */
#define PN532_SPI_WAKE_PULSE_MS 4

/* SPIstatus bits 7..4 and 1 (PN532/C1 table 125). */
#define PN532_SPI_STATUS_RESERVED 0xF2

typedef struct
{
    pn532_bus_t         base;
    spi_device_handle_t spi_handle;
    spi_host_device_t   host_id;
    gpio_num_t          nss;
    spi_transaction_t  *trans;
    uint8_t            *tx_buffer;
    uint8_t            *rx_buffer;
    bool                line_fault; /* last status byte had a reserved bit set */
} pn532_spi_bus_t;

/* Hosts initialised by this driver and how many PN532 devices sit on each.
 * Init/destroy are expected from one task; there is no locking. */
static struct
{
    bool    bus_owned;
    uint8_t devices;
} s_spi_hosts[SPI_HOST_MAX];

static void pn532_spi_host_release(spi_host_device_t host_id)
{
    if (s_spi_hosts[host_id].devices > 0 || !s_spi_hosts[host_id].bus_owned) {
        return;
    }
    esp_err_t err = spi_bus_free(host_id);
    if (err != ESP_OK) {
        /* Foreign devices are still attached; the application owns the rest. */
        ESP_LOGW(TAG, "spi_bus_free(%d) failed (%s)", (int)host_id, esp_err_to_name(err));
        return;
    }
    s_spi_hosts[host_id].bus_owned = false;
}

static pn532_spi_bus_t *pn532_spi_bus(pn532_bus_t *bus)
{
    return (pn532_spi_bus_t *)bus;
}

/* Called from the SPI ISR, which may run with the flash cache disabled when the
 * bus was initialised with ESP_INTR_FLAG_IRAM; gpio_set_level() lives in flash
 * unless CONFIG_GPIO_CTRL_FUNC_IN_IRAM, so write the register directly. */
static void IRAM_ATTR pn532_spi_pre_transfer(spi_transaction_t *trans)
{
    pn532_spi_bus_t *bus = (pn532_spi_bus_t *)trans->user;
    if (bus != NULL) {
        gpio_ll_set_level(&GPIO, bus->nss, 0);
        /* NSS setup time before the first clock edge. The PN532 documents
         * give no minimum outside Power Down (that wake-up is the pulse of
         * pn532_spi_bus_wake()); 100 us is the value this driver has been
         * run with on hardware since its first version. */
        esp_rom_delay_us(100);
    }
}

static void IRAM_ATTR pn532_spi_post_transfer(spi_transaction_t *trans)
{
    pn532_spi_bus_t *bus = (pn532_spi_bus_t *)trans->user;
    if (bus != NULL) {
        gpio_ll_set_level(&GPIO, bus->nss, 1);
    }
}

static bool pn532_spi_bus_write_command(pn532_bus_t *bus, const uint8_t *buffer, size_t len)
{
    pn532_spi_bus_t *spi_bus = pn532_spi_bus(bus);

    if (spi_bus == NULL || buffer == NULL || len == 0 || len > PN532_MAX_BUF_SIZE) {
        return false;
    }

    memcpy(spi_bus->tx_buffer, buffer, len);

    memset(spi_bus->trans, 0, sizeof(*spi_bus->trans));
    spi_bus->trans->cmd       = PN532_SPI_DATAWRITE;
    spi_bus->trans->length    = len * 8u;
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
    spi_bus->trans->cmd      = PN532_SPI_STATREAD;
    spi_bus->trans->rxlength = 8;
    spi_bus->trans->flags    = SPI_TRANS_USE_RXDATA;
    spi_bus->trans->user     = spi_bus;

    /* Polling avoids interrupt/task-switch latency for this 1-byte read,
     * which wait_ready() issues every tick. */
    esp_err_t err = spi_device_polling_transmit(spi_bus->spi_handle, spi_bus->trans);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_spi_bus_is_ready: failed (%s)", esp_err_to_name(err));
        return false;
    }

    /* PN532/C1 §8.3.5.7, SPIstatus: bit 0 READY, bit 2 RCV_OVR, bit 3 TR_FE
     * (set when the host read the FIFO empty, which every full-buffer read
     * of a short frame does; a busy chip then answers 0x08). UM0701-02 §6.2.5
     * tells the host to look at RDY only. The other bits are reserved and
     * read 0, so a set one (0xFF from an open or stuck-high MISO) means that
     * nothing is driving the line, and the byte does not count as ready. */
    uint8_t status = spi_bus->trans->rx_data[0];
    bool    fault  = (status & PN532_SPI_STATUS_RESERVED) != 0;
    if (fault != spi_bus->line_fault) {
        if (fault) {
            ESP_LOGW(TAG, "NSS %d: invalid status 0x%02X, MISO not driven (wiring, power, I0/I1, or chip hung)",
                     (int)spi_bus->nss, status);
        } else {
            ESP_LOGI(TAG, "NSS %d: status line valid again", (int)spi_bus->nss);
        }
        spi_bus->line_fault = fault;
    }
    return !fault && (status & PN532_SPI_READY) != 0;
}

/*
 * PN532/C1 §8.5.6 wake-up: NSS high → low edge, then T1 (max 2 ms) before any
 * SPI traffic; NSS stays low for PN532_SPI_WAKE_PULSE_MS. Do NOT send a host→PN532 ACK here — that would
 * abort the very next command (e.g. GetFirmwareVersion in init).
 * NSS must return high: on a shared bus a low NSS keeps this reader selected
 * while another one is being addressed.
 */
static void pn532_spi_wake_pulse(pn532_spi_bus_t *spi_bus)
{
    /* The pulse drives NSS outside a transaction. Hold the bus meanwhile, or
     * a reader polled from another task ends up selected together with this
     * one. */
    esp_err_t err = spi_device_acquire_bus(spi_bus->spi_handle, portMAX_DELAY);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "NSS %d: wake-up without bus lock (%s)", (int)spi_bus->nss, esp_err_to_name(err));
    }

    /* pn532_delay_ms() waits on wall-clock time: a few ms are zero ticks at
     * CONFIG_FREERTOS_HZ=100. */
    gpio_set_level(spi_bus->nss, 1);
    pn532_delay_ms(2);
    gpio_set_level(spi_bus->nss, 0);
    pn532_delay_ms(PN532_SPI_WAKE_PULSE_MS);
    gpio_set_level(spi_bus->nss, 1);

    if (err == ESP_OK) {
        spi_device_release_bus(spi_bus->spi_handle);
    }
}

static void pn532_spi_bus_wake(pn532_bus_t *bus)
{
    pn532_spi_bus_t *spi_bus = pn532_spi_bus(bus);

    if (spi_bus == NULL) {
        return;
    }
    pn532_spi_wake_pulse(spi_bus);
}

static void pn532_spi_bus_destroy(pn532_bus_t *bus)
{
    pn532_spi_bus_t *spi_bus = pn532_spi_bus(bus);

    if (spi_bus != NULL) {
        if (spi_bus->spi_handle != NULL) {
            esp_err_t err = spi_bus_remove_device(spi_bus->spi_handle);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "pn532_spi_bus_destroy: spi_bus_remove_device failed (%s)", esp_err_to_name(err));
            } else if (s_spi_hosts[spi_bus->host_id].devices > 0) {
                s_spi_hosts[spi_bus->host_id].devices--;
                pn532_spi_host_release(spi_bus->host_id);
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
    size_t max_transaction_len;
    if (spi_bus_get_max_transaction_len(host_id, &max_transaction_len) == ESP_OK) {
        return true;
    }

    spi_bus_config_t bus_config = {
        .mosi_io_num     = mosi,
        .miso_io_num     = miso,
        .sclk_io_num     = sck,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .data4_io_num    = -1,
        .data5_io_num    = -1,
        .data6_io_num    = -1,
        .data7_io_num    = -1,
        .max_transfer_sz = PN532_MAX_BUF_SIZE + 2,
    };

    esp_err_t err = spi_bus_initialize(host_id, &bus_config, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "pn532_spi_bus_init: spi_bus_initialize failed (%s)", esp_err_to_name(err));
        return false;
    }
    s_spi_hosts[host_id].bus_owned = true;
    return true;
}

/* DMA-capable scratch buffer for one PN532 frame. */
static uint8_t *pn532_spi_alloc_buffer(spi_host_device_t host_id)
{
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 4, 0)
    return spi_bus_dma_memory_alloc(host_id, PN532_MAX_BUF_SIZE + 2, 0);
#else
    /* spi_bus_dma_memory_alloc() appeared in ESP-IDF 5.4. */
    (void)host_id;
    return heap_caps_malloc(PN532_MAX_BUF_SIZE + 2, MALLOC_CAP_DMA);
#endif
}

static pn532_bus_t *pn532_spi_add_device(spi_host_device_t host_id, gpio_num_t nss, int clock_speed_hz)
{
    if (clock_speed_hz <= 0) {
        ESP_LOGW(TAG, "clock_speed_hz=%d, using default %d Hz", clock_speed_hz, PN532_SPI_DEFAULT_CLOCK_HZ);
        clock_speed_hz = PN532_SPI_DEFAULT_CLOCK_HZ;
    }
    if (clock_speed_hz > PN532_SPI_MAX_CLOCK_HZ) {
        ESP_LOGW(TAG, "clock_speed_hz=%d is above the PN532 maximum, using %d Hz", clock_speed_hz,
                 PN532_SPI_MAX_CLOCK_HZ);
        clock_speed_hz = PN532_SPI_MAX_CLOCK_HZ;
    }

    pn532_spi_bus_t *spi_bus = calloc(1, sizeof(*spi_bus));
    if (spi_bus == NULL) {
        return NULL;
    }

    /* Idle NSS high before the device joins the bus. The level is latched
     * before the pad becomes an output, so NSS does not dip low in between. */
    gpio_config_t nss_cfg = {
        .pin_bit_mask = (1ULL << nss),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_set_level(nss, 1);
    if (gpio_config(&nss_cfg) != ESP_OK) {
        free(spi_bus);
        return NULL;
    }
    gpio_set_level(nss, 1);
    spi_bus->host_id = host_id;
    spi_bus->nss     = nss;

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
        ESP_LOGE(TAG, "pn532_spi_add_device: failed to add SPI device");
        return NULL;
    }
    pn532_spi_wake_pulse(spi_bus);

    spi_bus->trans     = heap_caps_malloc(sizeof(*spi_bus->trans), MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    spi_bus->tx_buffer = pn532_spi_alloc_buffer(host_id);
    spi_bus->rx_buffer = pn532_spi_alloc_buffer(host_id);
    if (spi_bus->trans == NULL || spi_bus->tx_buffer == NULL || spi_bus->rx_buffer == NULL) {
        spi_bus_remove_device(spi_bus->spi_handle);
        free(spi_bus->trans);
        free(spi_bus->tx_buffer);
        free(spi_bus->rx_buffer);
        free(spi_bus);
        ESP_LOGE(TAG, "pn532_spi_add_device: failed to allocate SPI scratch buffers");
        return NULL;
    }

    s_spi_hosts[host_id].devices++;

    spi_bus->base.write_command = pn532_spi_bus_write_command;
    spi_bus->base.read_data     = pn532_spi_bus_read_data;
    spi_bus->base.is_ready      = pn532_spi_bus_is_ready;
    spi_bus->base.wake          = pn532_spi_bus_wake;
    spi_bus->base.destroy       = pn532_spi_bus_destroy;

    return &spi_bus->base;
}

pn532_bus_t *pn532_spi_init(spi_host_device_t host_id, gpio_num_t sck, gpio_num_t miso, gpio_num_t mosi, gpio_num_t nss,
                            int clock_speed_hz)
{
    if ((unsigned)host_id >= SPI_HOST_MAX) {
        return NULL;
    }
    if (!pn532_spi_bus_init(host_id, sck, miso, mosi)) {
        return NULL;
    }
    pn532_bus_t *bus = pn532_spi_add_device(host_id, nss, clock_speed_hz);
    if (bus == NULL) {
        pn532_spi_host_release(host_id);
    }
    return bus;
}

pn532_bus_t *pn532_spi_attach(spi_host_device_t host_id, gpio_num_t nss, int clock_speed_hz)
{
    size_t max_transaction_len;
    if ((unsigned)host_id >= SPI_HOST_MAX ||
        spi_bus_get_max_transaction_len(host_id, &max_transaction_len) != ESP_OK) {
        ESP_LOGE(TAG, "pn532_spi_attach: SPI host %d is not initialised", (int)host_id);
        return NULL;
    }
    /* Every response is read as one PN532_MAX_BUF_SIZE transaction. */
    if (max_transaction_len < PN532_MAX_BUF_SIZE) {
        ESP_LOGE(TAG, "pn532_spi_attach: SPI host %d carries %u bytes per transaction, the PN532 needs %d", (int)host_id,
                 (unsigned)max_transaction_len, PN532_MAX_BUF_SIZE);
        return NULL;
    }
    return pn532_spi_add_device(host_id, nss, clock_speed_hz);
}
