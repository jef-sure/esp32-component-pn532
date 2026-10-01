#include <stdlib.h>
#include <string.h>

#include "pn532-internal.h"
#include "pn532-ndef.h"
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
    MOCK_EXCHANGE_MI,
    MOCK_COMMUNICATE_THRU,
    MOCK_EXCHANGE_NAD,
    MOCK_TYPE4_APDU,
    MOCK_STATUS_TARGET_NOT_KNOWN,
    MOCK_TWO_LONG_ATS
} mock_mode_t;

typedef struct
{
    pn532_bus_t base;
    mock_mode_t mode;
    uint8_t     current_command;
    uint8_t     read_phase;
    uint8_t     commands[96];
    size_t      command_count;
    size_t      abort_count;
    size_t      drained_frames;
    uint8_t     list_initiator[16];
    size_t      list_initiator_len;
    bool        list_initiator_valid;
    uint8_t     pending_frames;
    uint8_t     mi_round;
    bool        exchange_loops_mi;
    uint32_t    host_baud; /* simulated link setting changed by resync */
    uint32_t    chip_baud; /* 0: chip answers at any host setting */
    size_t      resync_calls;
    size_t      nack_count;
    uint8_t     corrupt_responses; /* next N response frames get a broken DCS */
} mock_bus_t;

static const uint8_t ack_frame[]  = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
static const uint8_t nack_frame[] = {0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00};

static bool mock_write(pn532_bus_t *bus, const uint8_t *buffer, size_t len)
{
    mock_bus_t *mock = (mock_bus_t *)bus;

    if (len == sizeof(ack_frame) && memcmp(buffer, ack_frame, sizeof(ack_frame)) == 0) {
        mock->abort_count++;
        return true;
    }
    if (len == sizeof(nack_frame) && memcmp(buffer, nack_frame, sizeof(nack_frame)) == 0) {
        /* The PN532 resends the last response without a new ACK. */
        mock->nack_count++;
        mock->read_phase = 1;
        return true;
    }

    uint8_t command = buffer[3] == 0xFF ? buffer[9] : buffer[6];
    if (mock->mode == MOCK_LIST_TRANSPORT_ERROR && command == PN532_COMMAND_INLISTPASSIVETARGET) {
        return false;
    }

    /* Short frame layout: preamble(3) LEN ~LEN TF CMD then params. Capture the
     * InitiatorData of targeted InListPassiveTarget calls so tests can verify
     * cascade-tag insertion without real hardware. */
    if (command == PN532_COMMAND_INLISTPASSIVETARGET) {
        size_t params_len = (buffer[3] == 0xFF) ? (((size_t)buffer[5] << 8) | buffer[6]) : (size_t)buffer[3];
        params_len -= 2u; /* payload = TF + CMD */
        if (params_len > 2u) {
            size_t initiator_len = params_len - 2u; /* MaxTg + BrTy */
            const uint8_t *initiator = (buffer[3] == 0xFF) ? &buffer[10] : &buffer[7];
            TEST_ASSERT_LESS_OR_EQUAL(sizeof(mock->list_initiator), initiator_len);
            memcpy(mock->list_initiator, initiator, initiator_len);
            mock->list_initiator_len   = initiator_len;
            mock->list_initiator_valid = true;
        }
    }

    TEST_ASSERT_LESS_THAN(ARRAY_SIZE(mock->commands), mock->command_count);
    mock->commands[mock->command_count++] = command;
    mock->current_command                 = command;
    mock->read_phase                      = 0;
    return true;
}

/* Transport-side re-negotiation stand-in: switch to the chip's setting, ask the core to probe. */
static bool mock_resync(pn532_bus_t *bus, pn532_bus_probe_t probe, void *ctx)
{
    mock_bus_t *mock = (mock_bus_t *)bus;
    uint32_t    original = mock->host_baud;
    mock->resync_calls++;
    mock->host_baud = mock->chip_baud;
    if (probe(ctx)) {
        return true;
    }
    mock->host_baud = original;
    return false;
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
    case PN532_COMMAND_GETFIRMWAREVERSION: {
        static const uint8_t firmware[] = {0x32, 0x01, 0x06, 0x07};
        payload                         = firmware;
        payload_len                     = sizeof(firmware);
        break;
    }
    case PN532_COMMAND_GETGENERALSTATUS: {
        /* UM0701-02 format: Err Field NbTg [Tg BrRx BrTx Type]{NbTg} SAMstatus.
         * Two targets: Tg1 at 106 kbps ISO14443-3A, Tg2 at 212 kbps ISO14443-3A. */
        static const uint8_t general[] = {0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x00, 0x00};
        payload                        = general;
        payload_len                    = sizeof(general);
        break;
    }
    case PN532_COMMAND_INLISTPASSIVETARGET:
        payload     = mock->mode == MOCK_NO_CARD ? no_card : card;
        payload_len = mock->mode == MOCK_NO_CARD ? sizeof(no_card) : sizeof(card);
        if (mock->mode == MOCK_TWO_LONG_ATS) {
            /* NbTg=2; each: Tg ATQA(2) SAK=0x20 UIDLen=7 UID(7) ATS(TL=30): 85 bytes total. */
            static uint8_t two_ats[1 + 2 * 42];
            two_ats[0] = 2;
            for (uint8_t t = 0; t < 2; t++) {
                uint8_t *e = &two_ats[1 + t * 42];
                e[0]       = (uint8_t)(t + 1);
                e[1]       = 0x44;
                e[2]       = 0x03;
                e[3]       = 0x20;
                e[4]       = 7;
                memset(&e[5], 0x10 + t, 7);
                e[12] = 30;
                memset(&e[13], 0xA0, 29);
            }
            payload     = two_ats;
            payload_len = sizeof(two_ats);
        }
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
        /* Round 1: status 0x40 = MI chaining flag with the first fragment.
         * Round 2: status 0x00 terminates the chain with the tail fragment.
         * The driver must re-issue InDataExchange and concatenate both. */
        static const uint8_t first[]    = {0x40, 0x01, 0x02};
        static const uint8_t last[]     = {0x00, 0x03, 0x04, 0x05};
        const uint8_t       *payload    = (mock->mi_round == 0) ? first : last;
        size_t               payload_sz = (mock->mi_round == 0) ? sizeof(first) : sizeof(last);
        if (!mock->exchange_loops_mi) {
            mock->mi_round++;
        }
        mock_response_frame(mock->current_command, payload, payload_sz, buffer, len);
        return true;
    }

    if (mock->mode == MOCK_EXCHANGE_NAD && mock->current_command == PN532_COMMAND_INDATAEXCHANGE) {
        /* Status 0x80 = NAD present: the first payload byte (0x77) is the
         * node address and must be stripped from the caller's payload. */
        static const uint8_t nad[] = {0x80, 0x77, 0x10, 0x20};
        mock_response_frame(mock->current_command, nad, sizeof(nad), buffer, len);
        return true;
    }

    if (mock->mode == MOCK_TYPE4_APDU && mock->current_command == PN532_COMMAND_INDATAEXCHANGE) {
        static const uint8_t apdu_response[] = {0x00, 0x01, 0x02, 0x03, 0x90, 0x00};
        mock_response_frame(mock->current_command, apdu_response, sizeof(apdu_response), buffer, len);
        return true;
    }

    /* UM0701: 0x27 = target not known. InSelect/InDeselect must treat it as
     * a failure, not as an idempotent success. */
    if (mock->mode == MOCK_STATUS_TARGET_NOT_KNOWN &&
        (mock->current_command == PN532_COMMAND_INSELECT || mock->current_command == PN532_COMMAND_INDESELECT)) {
        static const uint8_t not_known[] = {0x27};
        mock_response_frame(mock->current_command, not_known, sizeof(not_known), buffer, len);
        return true;
    }

    if (mock->mode == MOCK_COMMUNICATE_THRU && mock->current_command == PN532_COMMAND_INCOMMUNICATETHRU) {
        /* Raw exchange: round 1 MI-fragments {0x11}, round 2 completes with
         * {0x22, 0x33}. Exercises both the raw path and its MI drain. */
        static const uint8_t first[]    = {0x40, 0x11};
        static const uint8_t last[]     = {0x00, 0x22, 0x33};
        const uint8_t       *payload    = (mock->mi_round == 0) ? first : last;
        size_t               payload_sz = (mock->mi_round == 0) ? sizeof(first) : sizeof(last);
        if (!mock->exchange_loops_mi) {
            mock->mi_round++;
        }
        mock_response_frame(mock->current_command, payload, payload_sz, buffer, len);
        return true;
    }

    mock_response_frame(mock->current_command, payload, payload_len, buffer, len);
    if (mock->corrupt_responses > 0) {
        mock->corrupt_responses--;
        buffer[7 + payload_len] ^= 0x5A; /* line noise in the DCS */
    }
    return true;
}

static bool mock_ready(pn532_bus_t *bus)
{
    mock_bus_t *mock = (mock_bus_t *)bus;
    if (mock->chip_baud != 0 && mock->host_baud != mock->chip_baud) {
        return false;
    }
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

TEST_CASE("DESFire detection reports unknown byte-addressed capacity", "[pn532][polling][desfire]")
{
    static const uint8_t desfire_saks[] = {0x20, 0x24};

    for (size_t index = 0; index < ARRAY_SIZE(desfire_saks); index++) {
        pn532_uid_t uid        = {.sak = desfire_saks[index]};
        uint16_t    blocks     = UINT16_MAX;
        uint16_t    block_size = UINT16_MAX;

        TEST_ASSERT_TRUE(pn532_14443_detect_card_type_and_capacity(&uid, &blocks, &block_size));
        TEST_ASSERT_EQUAL(PN532_MIFARE_DESFIRE, uid.subtype);
        TEST_ASSERT_EQUAL_UINT16(0, blocks);
        TEST_ASSERT_EQUAL_UINT16(1, block_size);
        TEST_ASSERT_EQUAL_UINT16(0, uid.blocks_count);
        TEST_ASSERT_EQUAL_UINT16(1, uid.block_size);
    }
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

TEST_CASE("targeted polling inserts cascade tags for cascaded UIDs", "[pn532][polling][cascade]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);

    pn532_uid_t uid = {0};
    uid.uid_length  = 7;
    uid.uid[0]      = 0x04;
    uid.uid[1]      = 0x11;
    uid.uid[2]      = 0x22;
    uid.uid[3]      = 0x33;
    uid.uid[4]      = 0x44;
    uid.uid[5]      = 0x55;
    uid.uid[6]      = 0x66;

    /* RF is off and tg is unset, so select_by_uid takes the targeted path
     * first. The mock answers with its fixed 4-byte card, so the overall call
     * falls back and fails; the captured targeted frame is what matters. */
    (void)pn532_14443_select_by_uid(&pn532, &uid);
    TEST_ASSERT_TRUE(mock.list_initiator_valid);
    TEST_ASSERT_EQUAL(8u, mock.list_initiator_len);
    TEST_ASSERT_EQUAL_UINT8(0x88, mock.list_initiator[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(uid.uid, &mock.list_initiator[1], 7);

    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    uid.uid_length = 10;
    for (int i = 0; i < 10; i++) {
        uid.uid[i] = (uint8_t)(0xA0 + i);
    }
    (void)pn532_14443_select_by_uid(&pn532, &uid);
    TEST_ASSERT_TRUE(mock.list_initiator_valid);
    TEST_ASSERT_EQUAL(12u, mock.list_initiator_len);
    const uint8_t cascaded10[] = {0x88, 0xA0, 0xA1, 0xA2, 0x88, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(cascaded10, mock.list_initiator, sizeof(cascaded10));
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

    /* Link check first (so a silent chip can be resynced), then SAM config,
     * retries, RF off. */
    const uint8_t expected[] = {PN532_COMMAND_GETFIRMWAREVERSION, PN532_COMMAND_SAMCONFIGURATION,
                                PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_RFCONFIGURATION};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
}

TEST_CASE("recover re-negotiates a link that went silent", "[pn532][recover][resync]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    mock.base.resync = mock_resync;
    mock.host_baud   = 921600;
    mock.chip_baud   = 115200; /* module power-cycled back to its default rate */

    TEST_ASSERT_TRUE(pn532_recover(&pn532));
    TEST_ASSERT_EQUAL(1, mock.resync_calls);
    TEST_ASSERT_EQUAL_UINT32(115200, mock.host_baud);

    /* Without a transport resync hook a silent chip fails recovery. */
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    mock.host_baud = 921600;
    mock.chip_baud = 115200;
    TEST_ASSERT_FALSE(pn532_recover(&pn532));
}

TEST_CASE("corrupted response is recovered by NACK retransmission", "[pn532][nack]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    mock.corrupt_responses = 1;

    TEST_ASSERT_NOT_EQUAL(0, pn532_get_firmware_version(&pn532));
    TEST_ASSERT_EQUAL(1, mock.nack_count);
    /* The command itself is not re-executed. */
    const uint8_t expected[] = {PN532_COMMAND_GETFIRMWAREVERSION};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));

    /* Persistent corruption gives up after the bounded retries. */
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    mock.corrupt_responses = 10;
    TEST_ASSERT_EQUAL(0, pn532_get_firmware_version(&pn532));
    TEST_ASSERT_EQUAL(2, mock.nack_count);
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

TEST_CASE("MI chained data is assembled across exchange rounds", "[pn532][exchange][mi]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_EXCHANGE_MI, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    uint8_t rx[16];
    size_t  rx_len = sizeof(rx);
    /* Round 1 replies status 0x40 (MI) with {0x01,0x02}; round 2 replies
     * status 0x00 with {0x03,0x04,0x05}. The driver must re-issue
     * InDataExchange and deliver the concatenated 5-byte payload. */
    TEST_ASSERT_TRUE(pn532_in_data_exchange(&pn532, (const uint8_t *)"\x30\x00", 2, rx, &rx_len, 100));
    TEST_ASSERT_EQUAL(5, rx_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0x01, 0x02, 0x03, 0x04, 0x05}), rx, 5);
    TEST_ASSERT_TRUE(pn532.session_opened);
    TEST_ASSERT_EQUAL(2, mock.command_count);

    /* A chain that never clears MI is cut off instead of looping forever;
     * the session is dropped so the next exchange re-selects. The large rx
     * buffer keeps the round guard, not capacity, as the limiting factor. */
    mock.mode              = MOCK_EXCHANGE_MI;
    mock.mi_round          = 0;
    mock.exchange_loops_mi = true;
    uint8_t loop_rx[PN532_MAX_BUF_SIZE];
    rx_len = sizeof(loop_rx);
    TEST_ASSERT_FALSE(pn532_in_data_exchange(&pn532, (const uint8_t *)"\x30\x00", 2, loop_rx, &rx_len, 100));
    TEST_ASSERT_FALSE(pn532.session_opened);
}

TEST_CASE("MI chain capacity shortfall reports the required size", "[pn532][exchange][mi]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_EXCHANGE_MI, send_buf, recv_buf);
    pn532.inListedTag = 1;

    uint8_t rx[3];
    size_t  rx_len = sizeof(rx);
    /* Total payload is 5 bytes; the 3-byte buffer cannot hold the chain. The
     * call fails and reports the required size through rx_len. */
    TEST_ASSERT_FALSE(pn532_in_data_exchange(&pn532, (const uint8_t *)"\x30\x00", 2, rx, &rx_len, 100));
    TEST_ASSERT_EQUAL(5, rx_len);
}

TEST_CASE("get general status decodes diagnostics fields", "[pn532][status]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);

    /* Real chip-format reply (UM0701-02): Err Field NbTg then per-target
     * 4-byte entries and the trailing SAM status byte. */
    pn532_general_status_t status;
    TEST_ASSERT_TRUE(pn532_get_general_status(&pn532, &status));
    TEST_ASSERT_EQUAL_UINT8(0, status.error);
    TEST_ASSERT_TRUE(status.field_present);
    TEST_ASSERT_EQUAL_UINT8(2, status.targets_count);
    TEST_ASSERT_EQUAL_UINT8(1, status.targets[0].tg);
    TEST_ASSERT_EQUAL_UINT8(0x00, status.targets[0].br_rx);
    TEST_ASSERT_EQUAL_UINT8(0x00, status.targets[0].br_tx);
    TEST_ASSERT_EQUAL_UINT8(0x00, status.targets[0].type);
    TEST_ASSERT_EQUAL_UINT8(2, status.targets[1].tg);
    TEST_ASSERT_EQUAL_UINT8(0x01, status.targets[1].br_rx);
    TEST_ASSERT_EQUAL_UINT8(0x01, status.targets[1].br_tx);
    TEST_ASSERT_EQUAL_UINT8(0x00, status.targets[1].type);
    TEST_ASSERT_TRUE(status.sam_status_valid);
    TEST_ASSERT_EQUAL_UINT8(0x00, status.sam_status);

    const uint8_t expected[] = {PN532_COMMAND_GETGENERALSTATUS};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
}

TEST_CASE("in communicate thru forwards raw bits and drains MI", "[pn532][thru]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_COMMUNICATE_THRU, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    uint8_t rx[16];
    size_t  rx_len = sizeof(rx);
    TEST_ASSERT_TRUE(pn532_in_communicate_thru(&pn532, (const uint8_t *)"\xE0\x80", 2, rx, &rx_len, 100));
    TEST_ASSERT_EQUAL(3, rx_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0x11, 0x22, 0x33}), rx, 3);
    TEST_ASSERT_TRUE(pn532.session_opened);
    TEST_ASSERT_EQUAL(2, mock.command_count);

    const uint8_t expected[] = {PN532_COMMAND_INCOMMUNICATETHRU, PN532_COMMAND_INCOMMUNICATETHRU};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
}

TEST_CASE("NAD byte is stripped from exchange payload", "[pn532][exchange][nad]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_EXCHANGE_NAD, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    uint8_t rx[16];
    size_t  rx_len = sizeof(rx);
    /* Status 0x80 = NAD present; payload {0x77, 0x10, 0x20} must surface as
     * {0x10, 0x20} with the node-address byte consumed. */
    TEST_ASSERT_TRUE(pn532_in_data_exchange(&pn532, (const uint8_t *)"\x30\x00", 2, rx, &rx_len, 100));
    TEST_ASSERT_EQUAL(2, rx_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0x10, 0x20}), rx, 2);
    TEST_ASSERT_TRUE(pn532.session_opened);
}

TEST_CASE("ISO-DEP exchange enforces the PN532 host frame size", "[pn532][exchange][apdu]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    /* Extended PN532 frame overhead plus Tg consumes 13 bytes. */
    uint8_t max_apdu[PN532_MAX_BUF_SIZE - 13u] = {0};
    uint8_t response[1];
    size_t  response_len = sizeof(response);
    TEST_ASSERT_TRUE(pn532_14443_4_transceive(&pn532, max_apdu, sizeof(max_apdu), response, &response_len));
    TEST_ASSERT_EQUAL(0u, response_len);
    TEST_ASSERT_EQUAL(1u, mock.command_count);

    uint8_t oversized_apdu[PN532_MAX_BUF_SIZE - 12u] = {0};
    response_len = sizeof(response);
    TEST_ASSERT_FALSE(
        pn532_14443_4_transceive(&pn532, oversized_apdu, sizeof(oversized_apdu), response, &response_len));
    TEST_ASSERT_EQUAL(1u, mock.command_count);
}

TEST_CASE("ISO-DEP exchange uses the existing selected-target lifecycle", "[pn532][exchange][apdu]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);

    static const uint8_t apdu[] = {0x00, 0xCA, 0x00, 0x00, 0x10};
    uint8_t response[1];
    size_t  response_len = sizeof(response);

    TEST_ASSERT_FALSE(pn532_14443_4_transceive(&pn532, apdu, sizeof(apdu), response, &response_len));
    TEST_ASSERT_EQUAL(0u, mock.command_count);

    pn532.inListedTag = 1;
    response_len = sizeof(response);
    TEST_ASSERT_TRUE(pn532_14443_4_transceive(&pn532, apdu, sizeof(apdu), response, &response_len));
    TEST_ASSERT_TRUE(pn532.session_opened);
    const uint8_t first_exchange[] = {PN532_COMMAND_INSELECT, PN532_COMMAND_INDATAEXCHANGE};
    assert_commands(&mock, first_exchange, ARRAY_SIZE(first_exchange));

    response_len = sizeof(response);
    TEST_ASSERT_TRUE(pn532_14443_4_transceive(&pn532, apdu, sizeof(apdu), response, &response_len));
    const uint8_t repeated_exchange[] = {
        PN532_COMMAND_INSELECT,
        PN532_COMMAND_INDATAEXCHANGE,
        PN532_COMMAND_INDATAEXCHANGE,
    };
    assert_commands(&mock, repeated_exchange, ARRAY_SIZE(repeated_exchange));
}

TEST_CASE("Type 4 helpers delegate APDUs to InDataExchange", "[pn532][exchange][apdu]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_TYPE4_APDU, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    static const uint8_t file_id[] = {0xE1, 0x03};
    TEST_ASSERT_TRUE(pn532_14443_4_select_file(&pn532, file_id, sizeof(file_id)));

    uint8_t data[3];
    size_t  data_len = sizeof(data);
    TEST_ASSERT_TRUE(pn532_14443_4_read_binary(&pn532, 0, sizeof(data), data, &data_len));
    TEST_ASSERT_EQUAL(3u, data_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0x01, 0x02, 0x03}), data, data_len);

    const uint8_t expected[] = {PN532_COMMAND_INDATAEXCHANGE, PN532_COMMAND_INDATAEXCHANGE};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
}

TEST_CASE("InSelect and InDeselect reject the target-not-known status", "[pn532][status]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_STATUS_TARGET_NOT_KNOWN, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    /* InSelect with 0x27 stays a hard error: selecting a target the chip
     * does not know must fail so the caller re-polls. */
    TEST_ASSERT_FALSE(pn532_in_select(&pn532, 1));
    TEST_ASSERT_FALSE(pn532.session_opened);

    /* InDeselect/InRelease with 0x27 mean the chip already lost the target:
     * mirror the NXP TAMA reference and close our session as a success so
     * poll loops do not wedge; both also clear the stale listed handle so
     * a later auto-InSelect cannot hit 0x27 forever. */
    mock_init(&mock, &pn532, MOCK_STATUS_TARGET_NOT_KNOWN, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;
    TEST_ASSERT_TRUE(pn532_deselect_target(&pn532));
    TEST_ASSERT_FALSE(pn532.session_opened);
    TEST_ASSERT_EQUAL_UINT8(0, pn532.inListedTag);

    mock_init(&mock, &pn532, MOCK_STATUS_TARGET_NOT_KNOWN, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;
    TEST_ASSERT_TRUE(pn532_release_target(&pn532));
    TEST_ASSERT_EQUAL_UINT8(0, pn532.inListedTag);
    TEST_ASSERT_FALSE(pn532.session_opened);
}

TEST_CASE("in communicate thru requires an active target", "[pn532][thru]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_COMMUNICATE_THRU, send_buf, recv_buf);
    pn532.inListedTag = 0;

    uint8_t rx[16];
    size_t  rx_len = sizeof(rx);
    /* No listed target: the call must fail locally without touching the bus,
     * instead of burning an RF timeout. */
    TEST_ASSERT_FALSE(pn532_in_communicate_thru(&pn532, (const uint8_t *)"\xE0", 1, rx, &rx_len, 100));
    TEST_ASSERT_EQUAL(0, mock.command_count);
}

TEST_CASE("NDEF CF chunks are assembled into one logical record", "[pn532][ndef][chunk]")
{
    static const uint8_t encoded[] = {
        0xB1, 0x01, 0x03, 'T', 'h', 'e', 'l', /* MB | CF | SR, first chunk */
        0x56, 0x00, 0x02, 'l', 'o',           /* ME | SR, TNF_UNCHANGED */
    };

    ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(NDEF_OK, ndef_parse_message(encoded, sizeof(encoded), &message));
    TEST_ASSERT_NOT_NULL(message);
    TEST_ASSERT_EQUAL(1, message->record_count);
    TEST_ASSERT_EQUAL(NDEF_TNF_WELL_KNOWN, message->records[0].tnf);
    TEST_ASSERT_EQUAL_UINT8('T', message->records[0].type[0]);
    TEST_ASSERT_EQUAL(5, message->records[0].payload_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("hello", message->records[0].payload, 5);
    ndef_free_parsed_message(message);
}

TEST_CASE("NDEF chunk sequence can precede another record", "[pn532][ndef][chunk]")
{
    static const uint8_t encoded[] = {
        0xB1, 0x01, 0x02, 'T', 'h',  'e', /* MB | CF | SR, first chunk */
        0x36, 0x00, 0x02, 'l', 'l',       /* CF | SR, middle chunk */
        0x16, 0x00, 0x01, 'o',            /* SR, final chunk */
        0x51, 0x01, 0x02, 'U', 0x00, 'x'  /* ME | SR, normal record */
    };

    ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(NDEF_OK, ndef_parse_message(encoded, sizeof(encoded), &message));
    TEST_ASSERT_EQUAL(2, message->record_count);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("hello", message->records[0].payload, 5);
    TEST_ASSERT_EQUAL_UINT8('U', message->records[1].type[0]);
    TEST_ASSERT_EQUAL(2, message->records[1].payload_len);
    ndef_free_parsed_message(message);
}

TEST_CASE("NDEF orphan continuation chunk is rejected", "[pn532][ndef][chunk]")
{
    static const uint8_t encoded[] = {
        0xD6, 0x00, 0x01, 'x', /* MB | ME | SR, TNF_UNCHANGED without first chunk */
    };

    ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(NDEF_ERR_PARSE_FAILED, ndef_parse_message(encoded, sizeof(encoded), &message));
    TEST_ASSERT_NULL(message);
}

TEST_CASE("APDU command parsing handles short cases and rejects malformed frames", "[pn532][apdu]")
{
    static const uint8_t case1[] = {0x00, 0xA4, 0x04, 0x00};
    static const uint8_t case2s[] = {0x00, 0xCA, 0x00, 0x00, 0x10};
    static const uint8_t case2s_max[] = {0x00, 0xCA, 0x00, 0x00, 0x00};
    static const uint8_t case3s[] = {0x00, 0xD0, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03};
    static const uint8_t case4s[] = {0x00, 0xD0, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x10};
    static const uint8_t case4s_max[] = {0x00, 0xD0, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};

    pn532_apdu_command_t command;
    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_parse_command(case1, sizeof(case1), &command));
    TEST_ASSERT_EQUAL_UINT8(0x00, command.cla);
    TEST_ASSERT_EQUAL_UINT8(0xA4, command.ins);
    TEST_ASSERT_EQUAL_UINT8(0x04, command.p1);
    TEST_ASSERT_EQUAL_UINT8(0x00, command.p2);
    TEST_ASSERT_NULL(command.data);
    TEST_ASSERT_EQUAL(0, command.data_len);
    TEST_ASSERT_FALSE(command.has_le);

    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_parse_command(case2s, sizeof(case2s), &command));
    TEST_ASSERT_NULL(command.data);
    TEST_ASSERT_TRUE(command.has_le);
    TEST_ASSERT_EQUAL_UINT16(16, command.le);

    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_parse_command(case2s_max, sizeof(case2s_max), &command));
    TEST_ASSERT_TRUE(command.has_le);
    TEST_ASSERT_EQUAL_UINT16(256, command.le);

    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_parse_command(case3s, sizeof(case3s), &command));
    TEST_ASSERT_EQUAL_PTR(&case3s[5], command.data);
    TEST_ASSERT_EQUAL(3u, command.data_len);
    TEST_ASSERT_FALSE(command.has_le);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0x01, 0x02, 0x03}), command.data, 3);

    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_parse_command(case4s, sizeof(case4s), &command));
    TEST_ASSERT_EQUAL_PTR(&case4s[5], command.data);
    TEST_ASSERT_TRUE(command.has_le);
    TEST_ASSERT_EQUAL_UINT16(16, command.le);

    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_parse_command(case4s_max, sizeof(case4s_max), &command));
    TEST_ASSERT_TRUE(command.has_le);
    TEST_ASSERT_EQUAL_UINT16(256, command.le);

    static const uint8_t too_short[] = {0x00, 0xA4, 0x04};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_parse_command(too_short, sizeof(too_short), &command));

    static const uint8_t bad_lc[] = {0x00, 0xD0, 0x00, 0x00, 0x05, 0x01, 0x02};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_parse_command(bad_lc, sizeof(bad_lc), &command));

    static const uint8_t extra_byte[] = {0x00, 0xD0, 0x00, 0x00, 0x01, 0xAA, 0x10, 0xFF};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_parse_command(extra_byte, sizeof(extra_byte), &command));

    static const uint8_t extended[] = {0x00, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA};
    TEST_ASSERT_EQUAL(ESP_ERR_NOT_SUPPORTED, pn532_apdu_parse_command(extended, sizeof(extended), &command));

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_parse_command(NULL, 0, &command));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_parse_command(case1, sizeof(case1), NULL));
}

TEST_CASE("APDU response parsing and building preserve data and status word", "[pn532][apdu]")
{
    static const uint8_t status_only[] = {0x90, 0x00};
    pn532_apdu_response_t response;
    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_parse_response(status_only, sizeof(status_only), &response));
    TEST_ASSERT_EQUAL_PTR(status_only, response.data);
    TEST_ASSERT_EQUAL(0u, response.data_len);
    TEST_ASSERT_EQUAL_HEX16(PN532_APDU_SW_SUCCESS, pn532_apdu_get_status(&response));
    TEST_ASSERT_EQUAL_HEX16(0, pn532_apdu_get_status(NULL));

    static const uint8_t raw[] = {0x01, 0x02, 0x03, 0x6A, 0x86};
    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_parse_response(raw, sizeof(raw), &response));
    TEST_ASSERT_EQUAL_PTR(raw, response.data);
    TEST_ASSERT_EQUAL(3u, response.data_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0x01, 0x02, 0x03}), response.data, 3);
    TEST_ASSERT_EQUAL_HEX16(PN532_APDU_SW_WRONG_P1P2, pn532_apdu_get_status(&response));

    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_parse_response(raw, 1, &response));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_parse_response(NULL, 0, &response));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_parse_response(raw, sizeof(raw), NULL));

    uint8_t out[16];
    size_t  out_len = 0;
    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_build_response(out, sizeof(out), raw, 3, 0x90, 0x00, &out_len));
    TEST_ASSERT_EQUAL(5u, out_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0x01, 0x02, 0x03, 0x90, 0x00}), out, 5);

    TEST_ASSERT_EQUAL(ESP_OK, pn532_apdu_build_response(out, sizeof(out), NULL, 0, 0x90, 0x00, &out_len));
    TEST_ASSERT_EQUAL(2u, out_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(status_only, out, 2);

    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, pn532_apdu_build_response(out, 4, raw, 3, 0x90, 0x00, &out_len));
    TEST_ASSERT_EQUAL(0u, out_len);
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, pn532_apdu_build_response(out, 1, NULL, 0, 0x90, 0x00, &out_len));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_build_response(out, sizeof(out), NULL, 1, 0x90, 0x00, &out_len));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_build_response(NULL, sizeof(out), raw, 3, 0x90, 0x00, &out_len));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, pn532_apdu_build_response(out, sizeof(out), raw, 3, 0x90, 0x00, NULL));
}

TEST_CASE("init falls back to transport resync when the device stays silent", "[pn532][init][resync]")
{
    mock_bus_t mock;
    memset(&mock, 0, sizeof(mock));
    mock.base.write_command = mock_write;
    mock.base.read_data     = mock_read;
    mock.base.is_ready      = mock_ready;
    mock.base.resync        = mock_resync;
    mock.mode               = MOCK_CARD;
    mock.host_baud          = 115200;
    mock.chip_baud          = 57600;

    pn532_t *pn532 = pn532_init(&mock.base, GPIO_NUM_NC, GPIO_NUM_NC);
    TEST_ASSERT_NOT_NULL(pn532);
    TEST_ASSERT_EQUAL(1, mock.resync_calls);
    TEST_ASSERT_EQUAL_UINT32(57600, mock.host_baud);
    pn532_deinit(pn532, false);

    /* Resync is not consulted when the device answers right away. */
    mock.command_count = 0;
    mock.resync_calls  = 0;
    pn532              = pn532_init(&mock.base, GPIO_NUM_NC, GPIO_NUM_NC);
    TEST_ASSERT_NOT_NULL(pn532);
    TEST_ASSERT_EQUAL(0, mock.resync_calls);
    pn532_deinit(pn532, false);

    /* Failed resync keeps the init failure. */
    mock.command_count = 0;
    mock.host_baud     = 115200;
    mock.chip_baud     = 1;
    mock.base.resync   = NULL;
    TEST_ASSERT_NULL(pn532_init(&mock.base, GPIO_NUM_NC, GPIO_NUM_NC));
}

TEST_CASE("HSU baud change is rejected on non-UART transports", "[pn532][uart][baud]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);

    TEST_ASSERT_FALSE(pn532_uart_set_baud_rate(&pn532, 921600));
    TEST_ASSERT_EQUAL(0, mock.command_count);
}

TEST_CASE("two targets with long ATS are polled, not reported as transport error", "[pn532][polling][ats]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_TWO_LONG_ATS, send_buf, recv_buf);

    pn532_poll_status_t status;
    pn532_uids_array_t *uids = pn532_14443_get_all_uids_ex(&pn532, &status);
    TEST_ASSERT_EQUAL(PN532_POLL_FOUND, status);
    TEST_ASSERT_NOT_NULL(uids);
    TEST_ASSERT_EQUAL_UINT8(2, uids->uids_count);
    TEST_ASSERT_EQUAL_UINT8(2, uids->uids[1].tg);
    TEST_ASSERT_EQUAL_INT8(7, uids->uids[1].uid_length);
    free(uids);
}

void app_main(void)
{
    unity_run_menu();
}
