#pragma once
// Host stand-in for the ESP-IDF header: only what the PN532 sources use. host_spi_test.c implements it.
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"

typedef int spi_host_device_t;
#define SPI2_HOST    1
#define SPI3_HOST    2
#define SPI_HOST_MAX 3

typedef struct host_spi_dev_t *spi_device_handle_t;

#define SPI_DMA_CH_AUTO         3
#define SPI_DEVICE_BIT_LSBFIRST (1u << 0)
#define SPI_DEVICE_HALFDUPLEX   (1u << 4)
#define SPI_TRANS_USE_RXDATA    (1u << 2)

typedef struct
{
    int mosi_io_num;
    int miso_io_num;
    int sclk_io_num;
    int quadwp_io_num;
    int quadhd_io_num;
    int data4_io_num;
    int data5_io_num;
    int data6_io_num;
    int data7_io_num;
    int max_transfer_sz;
} spi_bus_config_t;

typedef struct
{
    uint8_t  command_bits;
    uint8_t  mode;
    int      clock_speed_hz;
    int      spics_io_num;
    uint32_t flags;
    int      queue_size;
} spi_device_interface_config_t;

typedef struct
{
    uint32_t flags;
    uint16_t cmd;
    size_t   length;
    size_t   rxlength;
    union
    {
        const void *tx_buffer;
        uint8_t     tx_data[4];
    };
    union
    {
        void   *rx_buffer;
        uint8_t rx_data[4];
    };
} spi_transaction_t;

esp_err_t spi_bus_initialize(spi_host_device_t host, const spi_bus_config_t *config, int dma_chan);
esp_err_t spi_bus_free(spi_host_device_t host);
esp_err_t spi_bus_add_device(spi_host_device_t host, const spi_device_interface_config_t *config,
                             spi_device_handle_t *handle);
esp_err_t spi_bus_remove_device(spi_device_handle_t handle);
esp_err_t spi_bus_get_max_transaction_len(spi_host_device_t host, size_t *max_bytes);
void     *spi_bus_dma_memory_alloc(spi_host_device_t host, size_t size, uint32_t extra_heap_caps);
esp_err_t spi_device_acquire_bus(spi_device_handle_t handle, TickType_t wait);
void      spi_device_release_bus(spi_device_handle_t handle);
esp_err_t spi_device_transmit(spi_device_handle_t handle, spi_transaction_t *trans);
esp_err_t spi_device_polling_transmit(spi_device_handle_t handle, spi_transaction_t *trans);
