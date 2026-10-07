// Host test runner and the few ESP-IDF functions the driver core calls.
// Time is simulated: delays advance a counter instead of sleeping, so timeout paths run at once.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "unity.h"

void app_main(void);

/* ---- Test registry ---- */

#define HOST_MAX_TESTS 256

static struct
{
    const char      *name;
    host_test_func_t func;
    int              line;
} host_tests[HOST_MAX_TESTS];
static size_t host_test_count;

void host_test_register(const char *name, host_test_func_t func, int line)
{
    if (host_test_count >= HOST_MAX_TESTS) {
        fprintf(stderr, "too many test cases\n");
        abort();
    }
    host_tests[host_test_count].name = name;
    host_tests[host_test_count].func = func;
    host_tests[host_test_count].line = line;
    host_test_count++;
}

void setUp(void)
{
}

void tearDown(void)
{
}

void unity_run_menu(void)
{
    for (size_t i = 0; i < host_test_count; i++) {
        UnityDefaultTestRun(host_tests[i].func, host_tests[i].name, host_tests[i].line);
    }
}

int main(void)
{
    UnityBegin("test_apps/polling/main/test_pn532_polling.c");
    app_main();
    return UnityEnd();
}

/* ---- Simulated time ---- */

static int64_t host_time_us;

int64_t esp_timer_get_time(void)
{
    // Every reading costs a microsecond, so loops that only compare timestamps terminate.
    return host_time_us++;
}

void esp_rom_delay_us(uint32_t us)
{
    host_time_us += us;
}

void vTaskDelay(TickType_t ticks)
{
    host_time_us += (int64_t)ticks * portTICK_PERIOD_MS * 1000;
}

/* ---- GPIO and queue: the tests run without IRQ and reset pins ---- */

esp_err_t gpio_config(const gpio_config_t *config)
{
    (void)config;
    return ESP_OK;
}

esp_err_t gpio_set_level(gpio_num_t gpio, uint32_t level)
{
    (void)gpio;
    (void)level;
    return ESP_OK;
}

int gpio_get_level(gpio_num_t gpio)
{
    (void)gpio;
    return 1;
}

esp_err_t gpio_set_intr_type(gpio_num_t gpio, gpio_int_type_t type)
{
    (void)gpio;
    (void)type;
    return ESP_OK;
}

esp_err_t gpio_install_isr_service(int flags)
{
    (void)flags;
    return ESP_OK;
}

esp_err_t gpio_isr_handler_add(gpio_num_t gpio, gpio_isr_t handler, void *arg)
{
    (void)gpio;
    (void)handler;
    (void)arg;
    return ESP_OK;
}

esp_err_t gpio_isr_handler_remove(gpio_num_t gpio)
{
    (void)gpio;
    return ESP_OK;
}

esp_err_t gpio_reset_pin(gpio_num_t gpio)
{
    (void)gpio;
    return ESP_OK;
}

const char *esp_err_to_name(esp_err_t code)
{
    (void)code;
    return "esp_err";
}

QueueHandle_t xQueueCreate(unsigned length, unsigned item_size)
{
    (void)length;
    (void)item_size;
    return calloc(1, 1);
}

void vQueueDelete(QueueHandle_t queue)
{
    free(queue);
}

BaseType_t xQueueReceive(QueueHandle_t queue, void *item, TickType_t ticks)
{
    (void)queue;
    (void)item;
    vTaskDelay(ticks);
    return pdFALSE;
}

BaseType_t xQueueSendFromISR(QueueHandle_t queue, const void *item, BaseType_t *woken)
{
    (void)queue;
    (void)item;
    (void)woken;
    return pdTRUE;
}

BaseType_t xQueueReset(QueueHandle_t queue)
{
    (void)queue;
    return pdTRUE;
}
