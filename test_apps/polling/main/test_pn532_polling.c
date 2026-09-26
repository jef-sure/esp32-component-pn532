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
    MOCK_LIST_TRANSPORT_ERROR,
    MOCK_ACK_TIMEOUT,
    MOCK_PENDING_RESPONSE,
    MOCK_EXCHANGE_MI
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
    size_t      drained_frames;
    uint8_t     pending_frames;
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

/*
 * Simulates the wedged-chip case behind requirement 1: the ACK never arrives
 * (is_ready() stays false), so pn532_execute_command() must fail after the
 * short ACK budget instead of the full response timeout.
 */
static bool mock_ack_never_ready(pn532_bus_t *bus)
{
    mock_bus_t *mock = (mock_bus_t *)bus;
    return !(mock->mode == MOCK_ACK_TIMEOUT && mock->read_phase == 0);
}

/*
 * Simulates the aborted-list drain case behind requirement 2: a large
 * InListPassiveTarget response (~65 bytes for two cards) keeps reporting
 * ready so the abort drain must keep reading until the buffer is empty.
 */
static bool mock_pending_response_ready(pn532_bus_t *bus)
{
    mock_bus_t *mock = (mock_bus_t *)bus;
    return mock->mode == MOCK_PENDING_RESPONSE && mock->pending_frames > 0;
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

    if (mock->mode == MOCK_PENDING_RESPONSE) {
        /* Two-card sized payload: bigger than the old 16-byte drain buffer. */
        static uint8_t pending[64] = {0x01};
        payload                    = pending;
        payload_len                = sizeof(pending);
        mock_response_frame(mock->current_command, payload, payload_len, buffer, len);
        mock->drained_frames++;
        if (mock->pending_frames > 0) {
            mock->pending_frames--;
        }
        return true;
    }

    if (mock->mode == MOCK_EXCHANGE_MI && mock->current_command == PN532_COMMAND_INDATAEXCHANGE) {
        /* Status byte 0x40: MI chaining flag set, error bits clear. */
        static const uint8_t mi[] = {0x40, 0xAA, 0xBB};
        mock_response_frame(mock->current_command, mi, sizeof(mi), buffer, len);
        return true;
    }

    mock_response_frame(mock->current_command, payload, payload_len, buffer, len);
    return true;
}

static bool mock_ready(pn532_bus_t *bus)
{
    mock_bus_t *mock = (mock_bus_t *)bus;
    if (mock->mode == MOCK_ACK_TIMEOUT) {
        return mock_ack_never_ready(bus);
    }
    if (mock->mode == MOCK_PENDING_RESPONSE) {
        return mock_pending_response_ready(bus);
    }
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
    pn532->ack_timeout_ms    = 1;
    pn532->irq               = GPIO_NUM_NC;
    pn532->rst               = GPIO_NUM_NC;
}

static void assert_commands(const mock_bus_t *mock, const uint8_t *expected, size_t count)
{
    TEST_ASSERT_EQUAL(count, mock->command_count);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, mock->commands, count);
}

TEST_CASE("poll ends previous session and does not select a target", "[pn532][polling]")
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
                                      PN532_COMMAND_INLISTPASSIVETARGET};

    TEST_ASSERT_EQUAL(PN532_POLL_FOUND, status);
    TEST_ASSERT_EQUAL_UINT8(1, uids->uids[0].tg);
    TEST_ASSERT_EQUAL_UINT8(0, pn532.inListedTag);
    TEST_ASSERT_FALSE(pn532.session_opened);
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
    TEST_ASSERT_TRUE(pn532_14443_select_by_uid(&first, &first_uids->uids[0]));
    TEST_ASSERT_TRUE(pn532_release_target(&first));
    TEST_ASSERT_TRUE(pn532_set_rf_off(&first));
    pn532_uids_array_t *second_uids = pn532_14443_get_all_uids_ex(&second, &second_status);

    const uint8_t first_expected[]  = {PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_INLISTPASSIVETARGET,
                                       PN532_COMMAND_INSELECT, PN532_COMMAND_INRELEASE, PN532_COMMAND_RFCONFIGURATION};
    const uint8_t second_expected[] = {PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_INLISTPASSIVETARGET};
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

TEST_CASE("ACK timeout is distinguishable from response timeout", "[pn532][timeout]")
{
    mock_bus_t ack_bus;
    mock_bus_t response_bus;
    pn532_t    ack_timeout;
    pn532_t    response_timeout;
    uint8_t    ack_send[PN532_MAX_BUF_SIZE]      = {0};
    uint8_t    ack_recv[PN532_MAX_BUF_SIZE]      = {0};
    uint8_t    response_send[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    response_recv[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&ack_bus, &ack_timeout, MOCK_ACK_TIMEOUT, ack_send, ack_recv);
    mock_init(&response_bus, &response_timeout, MOCK_LIST_TIMEOUT, response_send, response_recv);

    uint8_t response[4];
    size_t  response_len = sizeof(response);
    TEST_ASSERT_FALSE(
        pn532_execute_command(&ack_timeout, PN532_COMMAND_GETFIRMWAREVERSION, NULL, 0, response, &response_len, 500));
    TEST_ASSERT_EQUAL(PN532_COMMAND_STATUS_ACK_TIMEOUT, ack_timeout.last_command_status);
    TEST_ASSERT_EQUAL(1, ack_bus.abort_count);

    /* Response timeout still reports the plain TIMEOUT status. */
    TEST_ASSERT_FALSE(pn532_14443_get_all_uids_ex(&response_timeout, NULL));
    TEST_ASSERT_EQUAL(PN532_COMMAND_STATUS_TIMEOUT, response_timeout.last_command_status);

    /* A wedged transport maps to TRANSPORT_ERROR at the polling layer. */
    mock_init(&ack_bus, &ack_timeout, MOCK_ACK_TIMEOUT, ack_send, ack_recv);
    pn532_poll_status_t status;
    TEST_ASSERT_NULL(pn532_14443_get_all_uids_ex(&ack_timeout, &status));
    TEST_ASSERT_EQUAL(PN532_POLL_TRANSPORT_ERROR, status);
}

TEST_CASE("abort drains pending response frames completely", "[pn532][abort]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_PENDING_RESPONSE, send_buf, recv_buf);
    mock.pending_frames  = 1;
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    pn532_abort_current_command(&pn532);

    TEST_ASSERT_EQUAL(1, mock.drained_frames);
    TEST_ASSERT_EQUAL_UINT8(0, pn532.inListedTag);
    TEST_ASSERT_FALSE(pn532.session_opened);

    /* The next command parses a clean frame: no "invalid frame header". */
    mock.mode          = MOCK_CARD;
    mock.command_count = 0;
    pn532_poll_status_t status;
    pn532_uids_array_t *uids = pn532_14443_get_all_uids_ex(&pn532, &status);
    TEST_ASSERT_EQUAL(PN532_POLL_FOUND, status);
    TEST_ASSERT_EQUAL_UINT8(1, uids->uids[0].tg);
    free(uids);
}

TEST_CASE("recover restores runtime configuration without recreating the bus", "[pn532][recover]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    TEST_ASSERT_TRUE(pn532_recover(&pn532));
    TEST_ASSERT_EQUAL_UINT8(0, pn532.inListedTag);
    TEST_ASSERT_FALSE(pn532.session_opened);
    TEST_ASSERT_FALSE(pn532.is_rf_on);
    TEST_ASSERT_EQUAL(PN532_COMMAND_STATUS_OK, pn532.last_command_status);

    /* SAM config, retries, firmware version, RF off — in that order. */
    const uint8_t expected[] = {PN532_COMMAND_SAMCONFIGURATION, PN532_COMMAND_RFCONFIGURATION,
                                PN532_COMMAND_GETFIRMWAREVERSION, PN532_COMMAND_RFCONFIGURATION};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
}

TEST_CASE("rf settle delay and ack timeout are configurable", "[pn532][rf]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);

    /* Setters must not crash on NULL and store the requested values. */
    pn532_set_rf_settle_delay(NULL, 99);
    pn532_set_rf_settle_delay(&pn532, 0);
    TEST_ASSERT_EQUAL_UINT16(0, pn532.rf_settle_delay_ms);
    pn532_set_rf_settle_delay(&pn532, 35);
    TEST_ASSERT_EQUAL_UINT16(35, pn532.rf_settle_delay_ms);

    pn532_set_ack_timeout(NULL, 99);
    pn532_set_ack_timeout(&pn532, 5);
    TEST_ASSERT_EQUAL_UINT16(5, pn532.ack_timeout_ms);
}

TEST_CASE("MI chained data is not misread as an exchange error", "[pn532][exchange]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_EXCHANGE_MI, send_buf, recv_buf);
    pn532.inListedTag = 1;

    uint8_t rx[16];
    size_t  rx_len = sizeof(rx);
    /* Status byte 0x40 = MI (more information) — a chaining flag, not an
     * error per NXP ERROR_MASK 0x3F. The exchange must succeed and must not
     * touch the session state. */
    pn532.session_opened = true;
    TEST_ASSERT_TRUE(pn532_in_data_exchange(&pn532, (const uint8_t *)"\x30\x00", 2, rx, &rx_len, 100));
    TEST_ASSERT_TRUE(pn532.session_opened);
    TEST_ASSERT_EQUAL(2, rx_len);
    TEST_ASSERT_EQUAL_UINT8(0xAA, rx[0]);
}

void app_main(void)
{
    unity_run_menu();
}
