#pragma once
// Host stand-in for the TEST_CASE() macro of the ESP-IDF Unity test runner: every test case
// registers itself before main() and host_main.c runs them all.

typedef void (*host_test_func_t)(void);

void host_test_register(const char *name, host_test_func_t func, int line);
void unity_run_menu(void);

#define HOST_TEST_CONCAT_(a, b) a##b
#define HOST_TEST_CONCAT(a, b)  HOST_TEST_CONCAT_(a, b)

#define TEST_CASE(name_, desc_)                                                     \
    static void HOST_TEST_CONCAT(host_test_func_, __LINE__)(void);                  \
    __attribute__((constructor)) static void HOST_TEST_CONCAT(host_test_reg_, __LINE__)(void) \
    {                                                                               \
        host_test_register(name_, HOST_TEST_CONCAT(host_test_func_, __LINE__), __LINE__); \
    }                                                                               \
    static void HOST_TEST_CONCAT(host_test_func_, __LINE__)(void)
