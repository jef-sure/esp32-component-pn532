#pragma once
// Host stand-in for the ESP-IDF header: only what the PN532 sources use. host_i2c_test.c implements it.
#include <stddef.h>
#include <stdint.h>

#include "driver/gpio.h"
#include "esp_err.h"

typedef int i2c_port_num_t;
typedef struct host_i2c_bus_t *i2c_master_bus_handle_t;
typedef struct host_i2c_dev_t *i2c_master_dev_handle_t;

typedef enum { I2C_CLK_SRC_DEFAULT = 0 } i2c_clock_source_t;
typedef enum { I2C_ADDR_BIT_LEN_7 = 0 } i2c_addr_bit_len_t;

typedef struct
{
    i2c_port_num_t     i2c_port;
    gpio_num_t         sda_io_num;
    gpio_num_t         scl_io_num;
    i2c_clock_source_t clk_source;
    uint8_t            glitch_ignore_cnt;
    int                intr_priority;
    size_t             trans_queue_depth;
    struct
    {
        uint32_t enable_internal_pullup : 1;
    } flags;
} i2c_master_bus_config_t;

typedef struct
{
    i2c_addr_bit_len_t dev_addr_length;
    uint16_t           device_address;
    uint32_t           scl_speed_hz;
    uint32_t           scl_wait_us;
} i2c_device_config_t;

esp_err_t i2c_new_master_bus(const i2c_master_bus_config_t *config, i2c_master_bus_handle_t *bus);
esp_err_t i2c_del_master_bus(i2c_master_bus_handle_t bus);
esp_err_t i2c_master_get_bus_handle(i2c_port_num_t port, i2c_master_bus_handle_t *bus);
esp_err_t i2c_master_bus_add_device(i2c_master_bus_handle_t bus, const i2c_device_config_t *config,
                                    i2c_master_dev_handle_t *dev);
esp_err_t i2c_master_bus_rm_device(i2c_master_dev_handle_t dev);
esp_err_t i2c_master_transmit(i2c_master_dev_handle_t dev, const uint8_t *buffer, size_t len, int timeout_ms);
esp_err_t i2c_master_receive(i2c_master_dev_handle_t dev, uint8_t *buffer, size_t len, int timeout_ms);
esp_err_t i2c_master_probe(i2c_master_bus_handle_t bus, uint16_t address, int timeout_ms);
