#pragma once
// Host stand-in for the ESP-IDF header. Define HOST_TEST_VERBOSE to see the driver's log output.
#include <stdio.h>
#ifdef HOST_TEST_VERBOSE
#define HOST_LOG(level, tag, format, ...) printf("%s (%s) " format "\n", level, tag, ##__VA_ARGS__)
#else
// The arguments are still type-checked against the format, without being evaluated at run time.
#define HOST_LOG(level, tag, format, ...)                    \
    do {                                                     \
        if (0) {                                             \
            printf("%s" format, tag, ##__VA_ARGS__);         \
        }                                                    \
    } while (0)
#endif
#define ESP_LOGE(tag, format, ...) HOST_LOG("E", tag, format, ##__VA_ARGS__)
#define ESP_LOGW(tag, format, ...) HOST_LOG("W", tag, format, ##__VA_ARGS__)
#define ESP_LOGI(tag, format, ...) HOST_LOG("I", tag, format, ##__VA_ARGS__)
#define ESP_LOGD(tag, format, ...) HOST_LOG("D", tag, format, ##__VA_ARGS__)
