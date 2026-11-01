// The I2C transport against a stand-in for the ESP-IDF I2C master driver with a PN532 behind it.
// As in the real driver, a bus with a transaction queue returns ESP_OK before the transfer: the
// chip still gets what was written, but nothing reaches the read buffer and no error is visible.

#include <string.h>

#include "pn532-internal.h"
#include "unity.h"

#define FAKE_FIRMWARE 0x32010607u

static const uint8_t fake_ack[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};

static struct
{
    size_t  queue_depth;
    uint8_t rdy_status;  /* status byte while a frame waits */
    size_t  write_nacks; /* address NACKs still to come */
    size_t  read_nacks;
    bool    ack_waiting;
    uint8_t response[16];
    size_t  response_len;
} fake;

static void fake_take_command(uint8_t command)
{
    static const uint8_t firmware[] = {0x32, 0x01, 0x06, 0x07};
    size_t               params_len = (command == PN532_COMMAND_GETFIRMWAREVERSION) ? sizeof(firmware) : 0;
    uint8_t              checksum   = (uint8_t)(PN532_PN532TOHOST + command + 1);
    size_t               n          = 0;

    fake.response[n++] = PN532_PREAMBLE;
    fake.response[n++] = PN532_STARTCODE1;
    fake.response[n++] = PN532_STARTCODE2;
    fake.response[n++] = (uint8_t)(params_len + 2);
    fake.response[n++] = (uint8_t)(0u - (params_len + 2));
    fake.response[n++] = PN532_PN532TOHOST;
    fake.response[n++] = (uint8_t)(command + 1);
    for (size_t i = 0; i < params_len; i++) {
        fake.response[n++] = firmware[i];
        checksum += firmware[i];
    }
    fake.response[n++] = (uint8_t)(0u - checksum);
    fake.response[n++] = PN532_POSTAMBLE;

    fake.response_len = n;
    fake.ack_waiting  = true;
}

esp_err_t i2c_master_transmit(i2c_master_dev_handle_t dev, const uint8_t *buffer, size_t len, int timeout_ms)
{
    (void)dev;
    (void)timeout_ms;
    if (fake.queue_depth == 0 && fake.write_nacks > 0) {
        fake.write_nacks--;
        return ESP_ERR_INVALID_RESPONSE;
    }
    /* The ACK and NACK frames of the host are shorter than a command frame. */
    if (len > sizeof(fake_ack)) {
        fake_take_command(buffer[6]);
    }
    return ESP_OK;
}

esp_err_t i2c_master_receive(i2c_master_dev_handle_t dev, uint8_t *buffer, size_t len, int timeout_ms)
{
    (void)dev;
    (void)timeout_ms;
    if (fake.queue_depth != 0) {
        return ESP_OK;
    }
    if (fake.read_nacks > 0) {
        fake.read_nacks--;
        return ESP_ERR_INVALID_RESPONSE;
    }

    memset(buffer, 0, len);
    const uint8_t *frame     = fake.ack_waiting ? fake_ack : fake.response;
    size_t         frame_len = fake.ack_waiting ? sizeof(fake_ack) : fake.response_len;
    if (frame_len == 0) {
        return ESP_OK;
    }
    buffer[0] = fake.rdy_status;
    if (len == 1) {
        /* A status read alone keeps the frame: see pn532_i2c_bus_is_ready(). */
        return ESP_OK;
    }
    memcpy(buffer + 1, frame, frame_len < len - 1 ? frame_len : len - 1);
    if (fake.ack_waiting) {
        fake.ack_waiting = false;
    } else {
        fake.response_len = 0;
    }
    return ESP_OK;
}

esp_err_t i2c_new_master_bus(const i2c_master_bus_config_t *config, i2c_master_bus_handle_t *bus)
{
    fake.queue_depth = config->trans_queue_depth;
    *bus             = (i2c_master_bus_handle_t)&fake;
    return ESP_OK;
}

esp_err_t i2c_del_master_bus(i2c_master_bus_handle_t bus)
{
    (void)bus;
    return ESP_OK;
}

esp_err_t i2c_master_get_bus_handle(i2c_port_num_t port, i2c_master_bus_handle_t *bus)
{
    (void)port;
    *bus = (i2c_master_bus_handle_t)&fake;
    return ESP_OK;
}

esp_err_t i2c_master_bus_add_device(i2c_master_bus_handle_t bus, const i2c_device_config_t *config,
                                    i2c_master_dev_handle_t *dev)
{
    (void)bus;
    (void)config;
    *dev = (i2c_master_dev_handle_t)&fake;
    return ESP_OK;
}

esp_err_t i2c_master_bus_rm_device(i2c_master_dev_handle_t dev)
{
    (void)dev;
    return ESP_OK;
}

esp_err_t i2c_master_probe(i2c_master_bus_handle_t bus, uint16_t address, int timeout_ms)
{
    (void)bus;
    (void)address;
    (void)timeout_ms;
    return ESP_OK;
}

static pn532_t *fake_start(uint8_t rdy_status)
{
    memset(&fake, 0, sizeof(fake));
    fake.rdy_status = rdy_status;

    pn532_bus_t *bus = pn532_i2c_init(0, GPIO_NUM_NC, GPIO_NUM_NC, 0, 0);
    TEST_ASSERT_NOT_NULL(bus);
    pn532_t *pn532 = pn532_init(bus, GPIO_NUM_NC, GPIO_NUM_NC);
    TEST_ASSERT_NOT_NULL(pn532);
    return pn532;
}

TEST_CASE("i2c: pn532_i2c_init creates a bus that delivers read data", "[pn532][i2c]")
{
    pn532_t *pn532 = fake_start(0x01);

    TEST_ASSERT_EQUAL_HEX32(FAKE_FIRMWARE, pn532_get_firmware_version(pn532));
    pn532_deinit(pn532, true);
}

TEST_CASE("i2c: ready is bit 0 of the status byte", "[pn532][i2c]")
{
    pn532_t *pn532 = fake_start(0x81);

    TEST_ASSERT_EQUAL_HEX32(FAKE_FIRMWARE, pn532_get_firmware_version(pn532));
    pn532_deinit(pn532, true);
}

TEST_CASE("i2c: address NACKs of a busy chip are repeated", "[pn532][i2c]")
{
    pn532_t *pn532 = fake_start(0x01);

    fake.write_nacks = 2;
    fake.read_nacks  = 3;
    TEST_ASSERT_EQUAL_HEX32(FAKE_FIRMWARE, pn532_get_firmware_version(pn532));

    fake.write_nacks = 3;
    TEST_ASSERT_EQUAL_HEX32(0, pn532_get_firmware_version(pn532));
    pn532_deinit(pn532, true);
}
