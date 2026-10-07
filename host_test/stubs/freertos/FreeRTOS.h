#pragma once
// Host stand-in for the FreeRTOS header: a 100 Hz tick, as in the ESP-IDF default configuration.
#include <stdint.h>
typedef uint32_t TickType_t;
typedef int      BaseType_t;
#define pdFALSE              0
#define pdTRUE               1
#define portMAX_DELAY        0xFFFFFFFFu
#define portTICK_PERIOD_MS   10
#define pdMS_TO_TICKS(ms)    ((TickType_t)((ms) / portTICK_PERIOD_MS))
#define portYIELD_FROM_ISR() ((void)0)
