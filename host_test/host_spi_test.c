// The SPI transport against a stand-in for the ESP-IDF SPI master driver. As in ESP-IDF, the
// master driver of a host comes up with its first spi_bus_add_device() and goes with
// spi_bus_free(), so spi_bus_get_max_transaction_len() fails on a host that was initialised
// but has never had a device.

#include <stdlib.h>
#include <string.h>

#include "pn532-internal.h"
#include "unity.h"

struct host_spi_dev_t
{
    spi_host_device_t host;
};

static struct
{
    bool   initialised[SPI_HOST_MAX];
    bool   driver_up[SPI_HOST_MAX];
    size_t max_transfer_sz[SPI_HOST_MAX];
    int    devices[SPI_HOST_MAX];
} fake_spi;

esp_err_t spi_bus_initialize(spi_host_device_t host, const spi_bus_config_t *config, int dma_chan)
{
    (void)dma_chan;
    if (fake_spi.initialised[host]) {
        return ESP_ERR_INVALID_STATE;
    }
    fake_spi.initialised[host]     = true;
    fake_spi.max_transfer_sz[host] = (config->max_transfer_sz > 0) ? (size_t)config->max_transfer_sz : 4092;
    return ESP_OK;
}

esp_err_t spi_bus_free(spi_host_device_t host)
{
    if (!fake_spi.initialised[host] || fake_spi.devices[host] > 0) {
        return ESP_ERR_INVALID_STATE;
    }
    fake_spi.initialised[host] = false;
    fake_spi.driver_up[host]   = false;
    return ESP_OK;
}

esp_err_t spi_bus_add_device(spi_host_device_t host, const spi_device_interface_config_t *config,
                             spi_device_handle_t *handle)
{
    (void)config;
    if (!fake_spi.initialised[host]) {
        return ESP_ERR_INVALID_STATE;
    }
    struct host_spi_dev_t *dev = calloc(1, sizeof(*dev));
    if (dev == NULL) {
        return ESP_ERR_NO_MEM;
    }
    dev->host                = host;
    fake_spi.driver_up[host] = true;
    fake_spi.devices[host]++;
    *handle = dev;
    return ESP_OK;
}

esp_err_t spi_bus_remove_device(spi_device_handle_t handle)
{
    fake_spi.devices[handle->host]--;
    free(handle);
    return ESP_OK;
}

esp_err_t spi_bus_get_max_transaction_len(spi_host_device_t host, size_t *max_bytes)
{
    if (!fake_spi.driver_up[host]) {
        return ESP_ERR_INVALID_ARG;
    }
    *max_bytes = fake_spi.max_transfer_sz[host];
    return ESP_OK;
}

void *spi_bus_dma_memory_alloc(spi_host_device_t host, size_t size, uint32_t extra_heap_caps)
{
    (void)host;
    (void)extra_heap_caps;
    return calloc(1, size);
}

esp_err_t spi_device_acquire_bus(spi_device_handle_t handle, TickType_t wait)
{
    (void)handle;
    (void)wait;
    return ESP_OK;
}

void spi_device_release_bus(spi_device_handle_t handle)
{
    (void)handle;
}

esp_err_t spi_device_transmit(spi_device_handle_t handle, spi_transaction_t *trans)
{
    (void)handle;
    (void)trans;
    return ESP_OK;
}

esp_err_t spi_device_polling_transmit(spi_device_handle_t handle, spi_transaction_t *trans)
{
    (void)handle;
    (void)trans;
    return ESP_OK;
}

static void fake_spi_app_bus(size_t max_transfer_sz)
{
    memset(&fake_spi, 0, sizeof(fake_spi));
    spi_bus_config_t config = {.max_transfer_sz = (int)max_transfer_sz};
    TEST_ASSERT_EQUAL(ESP_OK, spi_bus_initialize(SPI2_HOST, &config, SPI_DMA_CH_AUTO));
}

TEST_CASE("spi: attach to a host the application initialised without devices", "[pn532][spi]")
{
    fake_spi_app_bus(PN532_MAX_BUF_SIZE + 2);

    pn532_bus_t *bus = pn532_spi_attach(SPI2_HOST, 5, 1000000);
    TEST_ASSERT_NOT_NULL(bus);
    TEST_ASSERT_EQUAL(1, fake_spi.devices[SPI2_HOST]);
    pn532_bus_destroy(bus);
    TEST_ASSERT_EQUAL(0, fake_spi.devices[SPI2_HOST]);
    TEST_ASSERT_TRUE(fake_spi.initialised[SPI2_HOST]); /* the application owns the bus */
}

TEST_CASE("spi: init reuses a host the application initialised without devices", "[pn532][spi]")
{
    fake_spi_app_bus(PN532_MAX_BUF_SIZE + 2);

    pn532_bus_t *bus = pn532_spi_init(SPI2_HOST, 18, 19, 23, 5, 1000000);
    TEST_ASSERT_NOT_NULL(bus);
    pn532_bus_destroy(bus);
    TEST_ASSERT_TRUE(fake_spi.initialised[SPI2_HOST]);
}

TEST_CASE("spi: a host that cannot carry a frame is refused", "[pn532][spi]")
{
    fake_spi_app_bus(64);

    TEST_ASSERT_NULL(pn532_spi_attach(SPI2_HOST, 5, 1000000));
    TEST_ASSERT_EQUAL(0, fake_spi.devices[SPI2_HOST]);
    TEST_ASSERT_NULL(pn532_spi_init(SPI2_HOST, 18, 19, 23, 5, 1000000));
    TEST_ASSERT_EQUAL(0, fake_spi.devices[SPI2_HOST]);
    TEST_ASSERT_TRUE(fake_spi.initialised[SPI2_HOST]);
}

TEST_CASE("spi: init creates its own host and frees it with the last reader", "[pn532][spi]")
{
    memset(&fake_spi, 0, sizeof(fake_spi));

    pn532_bus_t *bus_a = pn532_spi_init(SPI3_HOST, 18, 19, 23, 5, 1000000);
    pn532_bus_t *bus_b = pn532_spi_init(SPI3_HOST, 18, 19, 23, 17, 1000000);
    TEST_ASSERT_NOT_NULL(bus_a);
    TEST_ASSERT_NOT_NULL(bus_b);
    TEST_ASSERT_EQUAL(2, fake_spi.devices[SPI3_HOST]);
    pn532_bus_destroy(bus_a);
    TEST_ASSERT_TRUE(fake_spi.initialised[SPI3_HOST]);
    pn532_bus_destroy(bus_b);
    TEST_ASSERT_FALSE(fake_spi.initialised[SPI3_HOST]);
}

TEST_CASE("spi: attach to a host nobody initialised fails", "[pn532][spi]")
{
    memset(&fake_spi, 0, sizeof(fake_spi));

    TEST_ASSERT_NULL(pn532_spi_attach(SPI2_HOST, 5, 1000000));
    TEST_ASSERT_EQUAL(0, fake_spi.devices[SPI2_HOST]);
}
