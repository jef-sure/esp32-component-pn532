# Host run of the driver tests: no hardware and no ESP-IDF build needed.
# The tests are the ones of test_apps/polling; they drive the driver core through a mock bus.
# The Unity test framework is taken from an ESP-IDF checkout:
#   make test IDF_PATH=~/.espressif/v5.5.4/esp-idf
# or run it from a shell where ESP-IDF is activated.

ifeq ($(strip $(IDF_PATH)),)
$(error IDF_PATH is not set: activate ESP-IDF or pass IDF_PATH=<path to esp-idf>)
endif

UNITY_DIR := $(IDF_PATH)/components/unity/unity/src
BUILD_DIR ?= build

# The bus transports (src/pn532-bus-*.c) need the real drivers and are not built here.
DRIVER_SRCS := ../src/pn532.c ../src/pn532-14443.c ../src/pn532-mifare.c ../src/pn532-apdu.c ../src/pn532-ndef.c
TEST_SRCS   := ../test_apps/polling/main/test_pn532_polling.c host_main.c $(UNITY_DIR)/unity.c

CFLAGS += -std=gnu11 -g -O1 -Wall -Wno-unused-function -fsanitize=address,undefined -fno-sanitize-recover=undefined
CFLAGS += -Istubs -I../include -I../src -I. -I$(UNITY_DIR) -include host_test_case.h -DPN532_HOST_TEST

$(BUILD_DIR)/pn532_host_test: $(DRIVER_SRCS) $(TEST_SRCS) $(wildcard *.h) $(wildcard stubs/*.h stubs/*/*.h) \
                              $(wildcard ../include/*.h) $(wildcard ../src/*.h)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(DRIVER_SRCS) $(TEST_SRCS) -o $@

.PHONY: test clean
test: $(BUILD_DIR)/pn532_host_test
	$(BUILD_DIR)/pn532_host_test

clean:
	rm -rf $(BUILD_DIR)
