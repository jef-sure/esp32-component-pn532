# Host run of the driver tests: no hardware and no ESP-IDF build needed.
# The tests are the ones of test_apps/polling; they drive the driver core through a mock bus.
# The Unity test framework is taken from an ESP-IDF checkout:
#   make test IDF_PATH=~/.espressif/v5.5.4/esp-idf
# or run it from a shell where ESP-IDF is activated. Without ESP-IDF, point
# UNITY_DIR at the src directory of a Unity checkout:
#   make test UNITY_DIR=~/Unity/src

ifeq ($(strip $(UNITY_DIR)),)
ifeq ($(strip $(IDF_PATH)),)
$(error IDF_PATH is not set: activate ESP-IDF, pass IDF_PATH=<path to esp-idf> or UNITY_DIR=<path to Unity/src>)
endif
UNITY_DIR := $(IDF_PATH)/components/unity/unity/src
endif
BUILD_DIR ?= build

# The UART transport needs the real driver and is not built here; the I2C and SPI ones run
# against stand-ins of the ESP-IDF master drivers in host_i2c_test.c and host_spi_test.c.
DRIVER_SRCS := ../src/pn532.c ../src/pn532-14443.c ../src/pn532-mifare.c ../src/pn532-apdu.c ../src/pn532-ndef.c \
               ../src/pn532-bus-i2c.c ../src/pn532-bus-spi.c
TEST_SRCS   := ../test_apps/polling/main/test_pn532_polling.c host_main.c host_i2c_test.c host_spi_test.c \
               $(UNITY_DIR)/unity.c

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
