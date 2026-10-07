#pragma once
// Host stand-in for the FreeRTOS header.
#include "freertos/FreeRTOS.h"
typedef void *QueueHandle_t;
QueueHandle_t xQueueCreate(unsigned length, unsigned item_size);
void          vQueueDelete(QueueHandle_t queue);
BaseType_t    xQueueReceive(QueueHandle_t queue, void *item, TickType_t ticks);
BaseType_t    xQueueSendFromISR(QueueHandle_t queue, const void *item, BaseType_t *woken);
BaseType_t    xQueueReset(QueueHandle_t queue);
