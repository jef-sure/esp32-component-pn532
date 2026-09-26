#include <stdlib.h>
#include <string.h>

#include "pn532-internal.h"
#include "unity.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

typedef enum
{
    MOCK_CARD,
    MOCK_NO_CARD,
    MOCK_LIST_TIMEOUT,
    MOCK_LIST_TRANSPORT_ERROR
} mock_mode_t;

typedef struct
{
    pn532_bus_t base;
    mock_mode_t mode;
    uint8_t     current_command;
    uint8_t     read_phase;
    uint8_t     commands[16];
    size_t      command_count;
    size_t      abort_count;
} mock_bus_t;

static const uint8_t ack_frame[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};

static bool mock_write(pn532_bus_t *bus, const uint8_t *buffer, size_t len)
{
    mock_bus_t *mock = (mock_bus_t *)bus;

    if (len == sizeof(ack_frame) && memcmp(buffer, ack_frame, sizeof(ack_frame)) == 0) {
        mock->abort_count++;
        return true;
    }

    uint8_t command = buffer[3] == 0xFF ? buffer[9] : buffer[6];
    if (mock->mode == MOCK_LIST_TRANSPORT_ERROR && command == PN532_COMMAND_INLISTPASSIVETARGET) {
        return false;
    }

    TEST_ASSERT_LESS_THAN(ARRAY_SIZE(mock->commands), mock->command_count);
    mock->commands[mock->command_count++] = command;
    mock->current_command                 = command;
    mock->read_phase                      = 0;
    return true;
}

static void mock_response_frame(uint8_t command, const uint8_t *payload, size_t payload_len, uint8_t *buffer,
                                size_t buffer_len)
{
    TEST_ASSERT_GREATER_OR_EQUAL(payload_len + 9, buffer_len);
    memset(buffer, 0, buffer_len);

    uint8_t frame_len = (uint8_t)(payload_len + 2);
    buffer[2]         = 0xFF;
    buffer[3]         = frame_len;
    buffer[4]         = (uint8_t)(0u - frame_len);
    buffer[5]         = PN532_PN532TOHOST;
    buffer[6]         = (uint8_t)(command + 1);
    if (payload_len > 0) {
        memcpy(buffer + 7, payload, payload_len);
    }

    uint8_t checksum = PN532_PN532TOHOST + (uint8_t)(command + 1);
    for (size_t index = 0; index < payload_len; index++) {
        checksum += payload[index];
    }
    buffer[7 + payload_len] = (uint8_t)(0u - checksum);
    buffer[8 + payload_len] = 0x00;
}

static bool mock_read(pn532_bus_t *bus, uint8_t *buffer, size_t len)
{
    mock_bus_t *mock = (mock_bus_t *)bus;

    if (mock->read_phase++ == 0) {
        TEST_ASSERT_EQUAL(sizeof(ack_frame), len);
        memcpy(buffer, ack_frame, sizeof(ack_frame));
        return true;
    }

    static const uint8_t ok[]      = {0x00};
    static const uint8_t no_card[] = {0x00};
    static const uint8_t card[]    = {0x01, 0x01, 0x04, 0x00, 0x08, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t       *payload   = NULL;
    size_t               payload_len;

    switch (mock->current_command) {
    case PN532_COMMAND_RFCONFIGURATION:
        payload_len = 0;
        break;
    case PN532_COMMAND_INLISTPASSIVETARGET:
        payload     = mock->mode == MOCK_NO_CARD ? no_card : card;
        payload_len = mock->mode == MOCK_NO_CARD ? sizeof(no_card) : sizeof(card);
        break;
    default:
        payload     = ok;
        payload_len = sizeof(ok);
        break;
    }

    mock_response_frame(mock->current_command, payload, payload_len, buffer, len);
    return true;
}

static bool mock_ready(pn532_bus_t *bus)
{
    mock_bus_t *mock = (mock_bus_t *)bus;
    return !(mock->mode == MOCK_LIST_TIMEOUT && mock->current_command == PN532_COMMAND_INLISTPASSIVETARGET &&
             mock->read_phase > 0);
}

static void mock_init(mock_bus_t *mock, pn532_t *pn532, mock_mode_t mode, uint8_t *send_buf, uint8_t *recv_buf)
{
    memset(mock, 0, sizeof(*mock));
    memset(pn532, 0, sizeof(*pn532));
    mock->base.write_command = mock_write;
    mock->base.read_data     = mock_read;
    mock->base.is_ready      = mock_ready;
    mock->mode               = mode;
    pn532->bus               = &mock->base;
    pn532->send_buf          = send_buf;
    pn532->recv_buf          = recv_buf;
    pn532->timeout_ms        = 1;
    pn532->irq               = GPIO_NUM_NC;
    pn532->rst               = GPIO_NUM_NC;
}

static void assert_commands(const mock_bus_t *mock, const uint8_t *expected, size_t count)
{
    TEST_ASSERT_EQUAL(count, mock->command_count);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, mock->commands, count);
}

TEST_CASE("poll ends previous session before RF off and list", "[pn532][polling]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    pn532_poll_status_t status;
    pn532_uids_array_t *uids       = pn532_14443_get_all_uids_ex(&pn532, &status);
    const uint8_t       expected[] = {PN532_COMMAND_INRELEASE, PN532_COMMAND_RFCONFIGURATION,
                                      PN532_COMMAND_INLISTPASSIVETARGET, PN532_COMMAND_INSELECT};

    TEST_ASSERT_EQUAL(PN532_POLL_FOUND, status);
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
    free(uids);
}

TEST_CASE("two PN532 devices are polled sequentially", "[pn532][polling][spi]")
{
    mock_bus_t first_bus;
    mock_bus_t second_bus;
    pn532_t    first;
    pn532_t    second;
    uint8_t    first_send[PN532_MAX_BUF_SIZE]  = {0};
    uint8_t    first_recv[PN532_MAX_BUF_SIZE]  = {0};
    uint8_t    second_send[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    second_recv[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&first_bus, &first, MOCK_CARD, first_send, first_recv);
    mock_init(&second_bus, &second, MOCK_CARD, second_send, second_recv);

    pn532_poll_status_t first_status;
    pn532_poll_status_t second_status;
    pn532_uids_array_t *first_uids = pn532_14443_get_all_uids_ex(&first, &first_status);
    TEST_ASSERT_EQUAL(PN532_POLL_FOUND, first_status);
    TEST_ASSERT_TRUE(pn532_release_target(&first));
    TEST_ASSERT_TRUE(pn532_set_rf_off(&first));
    pn532_uids_array_t *second_uids = pn532_14443_get_all_uids_ex(&second, &second_status);

    const uint8_t first_expected[]  = {PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_INLISTPASSIVETARGET,
                                       PN532_COMMAND_INSELECT, PN532_COMMAND_INRELEASE, PN532_COMMAND_RFCONFIGURATION};
    const uint8_t second_expected[] = {PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_INLISTPASSIVETARGET,
                                       PN532_COMMAND_INSELECT};
    TEST_ASSERT_EQUAL(PN532_POLL_FOUND, second_status);
    assert_commands(&first_bus, first_expected, ARRAY_SIZE(first_expected));
    assert_commands(&second_bus, second_expected, ARRAY_SIZE(second_expected));
    free(first_uids);
    free(second_uids);
}

TEST_CASE("RF off invalidates target and session", "[pn532][polling]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    TEST_ASSERT_TRUE(pn532_set_rf_off(&pn532));
    TEST_ASSERT_EQUAL_UINT8(0, pn532.inListedTag);
    TEST_ASSERT_FALSE(pn532.session_opened);
    TEST_ASSERT_TRUE(pn532_release_target(&pn532));

    const uint8_t expected[] = {PN532_COMMAND_RFCONFIGURATION};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
}

TEST_CASE("no card, transport error, and timeout differ", "[pn532][polling]")
{
    mock_bus_t no_card_bus;
    mock_bus_t transport_bus;
    mock_bus_t timeout_bus;
    pn532_t    no_card;
    pn532_t    transport;
    pn532_t    timeout;
    uint8_t    no_card_send[PN532_MAX_BUF_SIZE]   = {0};
    uint8_t    no_card_recv[PN532_MAX_BUF_SIZE]   = {0};
    uint8_t    transport_send[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    transport_recv[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    timeout_send[PN532_MAX_BUF_SIZE]   = {0};
    uint8_t    timeout_recv[PN532_MAX_BUF_SIZE]   = {0};
    mock_init(&no_card_bus, &no_card, MOCK_NO_CARD, no_card_send, no_card_recv);
    mock_init(&transport_bus, &transport, MOCK_LIST_TRANSPORT_ERROR, transport_send, transport_recv);
    mock_init(&timeout_bus, &timeout, MOCK_LIST_TIMEOUT, timeout_send, timeout_recv);

    pn532_poll_status_t status;
    TEST_ASSERT_NULL(pn532_14443_get_all_uids_ex(&no_card, &status));
    TEST_ASSERT_EQUAL(PN532_POLL_NO_TARGET, status);
    TEST_ASSERT_NULL(pn532_14443_get_all_uids_ex(&transport, &status));
    TEST_ASSERT_EQUAL(PN532_POLL_TRANSPORT_ERROR, status);
    TEST_ASSERT_NULL(pn532_14443_get_all_uids_ex(&timeout, &status));
    TEST_ASSERT_EQUAL(PN532_POLL_TIMEOUT, status);
    TEST_ASSERT_EQUAL(1, timeout_bus.abort_count);
}

TEST_CASE("timeout recovery is isolated per instance", "[pn532][polling]")
{
    mock_bus_t first_bus;
    mock_bus_t second_bus;
    pn532_t    first;
    pn532_t    second;
    uint8_t    first_send[PN532_MAX_BUF_SIZE]  = {0};
    uint8_t    first_recv[PN532_MAX_BUF_SIZE]  = {0};
    uint8_t    second_send[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    second_recv[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&first_bus, &first, MOCK_LIST_TIMEOUT, first_send, first_recv);
    mock_init(&second_bus, &second, MOCK_NO_CARD, second_send, second_recv);
    second.inListedTag         = 2;
    second.session_opened      = true;
    second.last_command_status = PN532_COMMAND_STATUS_OK;

    pn532_poll_status_t status;
    TEST_ASSERT_NULL(pn532_14443_get_all_uids_ex(&first, &status));
    TEST_ASSERT_EQUAL(PN532_POLL_TIMEOUT, status);
    TEST_ASSERT_EQUAL_UINT8(0, first.inListedTag);
    TEST_ASSERT_FALSE(first.session_opened);
    TEST_ASSERT_EQUAL_UINT8(2, second.inListedTag);
    TEST_ASSERT_TRUE(second.session_opened);
    TEST_ASSERT_EQUAL(PN532_COMMAND_STATUS_OK, second.last_command_status);
}

TEST_CASE("legacy UID polling remains compatible", "[pn532][polling]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);

    pn532_uids_array_t *uids           = pn532_14443_get_all_uids(&pn532);
    const uint8_t       expected_uid[] = {0xDE, 0xAD, 0xBE, 0xEF};
    TEST_ASSERT_NOT_NULL(uids);
    TEST_ASSERT_EQUAL_UINT8(1, uids->uids_count);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_uid, uids->uids[0].uid, sizeof(expected_uid));
    free(uids);
}

void app_main(void)
{
    unity_run_menu();
}
