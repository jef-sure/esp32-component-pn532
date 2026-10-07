#pragma once
// Host stand-in for the ESP-IDF header.
#include <stdint.h>

#include "esp_err.h"

typedef int gpio_num_t;
#define GPIO_NUM_NC  (-1)
#define GPIO_NUM_MAX 64

typedef enum { GPIO_MODE_INPUT = 1, GPIO_MODE_OUTPUT = 2 } gpio_mode_t;
typedef enum { GPIO_PULLUP_DISABLE = 0, GPIO_PULLUP_ENABLE = 1 } gpio_pullup_t;
typedef enum { GPIO_PULLDOWN_DISABLE = 0, GPIO_PULLDOWN_ENABLE = 1 } gpio_pulldown_t;
typedef enum { GPIO_INTR_DISABLE = 0, GPIO_INTR_NEGEDGE = 2 } gpio_int_type_t;

typedef struct
{
    uint64_t        pin_bit_mask;
    gpio_mode_t     mode;
    gpio_pullup_t   pull_up_en;
    gpio_pulldown_t pull_down_en;
    gpio_int_type_t intr_type;
} gpio_config_t;

typedef void (*gpio_isr_t)(void *arg);

esp_err_t gpio_config(const gpio_config_t *config);
esp_err_t gpio_set_level(gpio_num_t gpio, uint32_t level);
int       gpio_get_level(gpio_num_t gpio);
esp_err_t gpio_set_intr_type(gpio_num_t gpio, gpio_int_type_t type);
esp_err_t gpio_install_isr_service(int flags);
esp_err_t gpio_isr_handler_add(gpio_num_t gpio, gpio_isr_t handler, void *arg);
esp_err_t gpio_isr_handler_remove(gpio_num_t gpio);
esp_err_t gpio_reset_pin(gpio_num_t gpio);
