#include <stdlib.h>
#include <string.h>

#include "pn532-internal.h"
#include "pn532-mifare.h"
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
    MOCK_RELEASE_PROTOCOL_ERROR,
    MOCK_TWO_LONG_ATS,
    MOCK_TYPE4_SELECT_V1,
    MOCK_AUTH_ERROR,
    MOCK_SIM_CARD
} mock_mode_t;

typedef struct mock_bus_t mock_bus_t;

/* Simulated card for MOCK_SIM_CARD: gets the request parameters of one
 * InDataExchange (Tg first) or InCommunicateThru and writes the response
 * payload, PN532 status byte first. */
typedef size_t (*mock_sim_card_t)(mock_bus_t *mock, uint8_t command, const uint8_t *request, size_t request_len,
                                  uint8_t *response);

struct mock_bus_t
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
    uint8_t     exchange_params[8][16]; /* per-round InDataExchange/Thru request params */
    size_t      exchange_params_len[8];
    size_t      exchange_rounds;
    uint8_t     pending_frames;
    uint8_t     mi_round;
    bool        exchange_loops_mi;
    uint32_t    host_baud; /* simulated link setting changed by resync */
    uint32_t    chip_baud; /* 0: chip answers at any host setting */
    size_t      resync_calls;
    size_t      nack_count;
    uint8_t     corrupt_responses; /* next N response frames get a broken DCS */
    uint8_t     two_ats_sak[2];    /* MOCK_TWO_LONG_ATS SAK per target; 0 selects 0x20 */
    uint8_t     card_sak;          /* MOCK_CARD SAK override; 0 selects 0x08 */
    uint8_t     tama_params;       /* last SetParameters flags; 0: never written (chip default, RATS on) */
    mock_sim_card_t sim_card;          /* MOCK_SIM_CARD: the card behind the PN532 */
    uint8_t         sim_request[32];
    size_t          sim_request_len;
    uint8_t        *sim_memory;    /* Type 2 pages or Classic blocks */
    size_t          sim_units;     /* number of pages / blocks in sim_memory */
    size_t          sim_reads;     /* READ commands the card answered */
    const uint8_t  *sim_version;   /* Type 2: 8-byte GET_VERSION answer, NULL when not supported */
    bool            sim_ulc;       /* Type 2: answers AUTHENTICATE (1Ah) like an Ultralight C */
    const uint8_t  *sim_cc_file;   /* Type 4: capability container file (15 bytes) */
    const uint8_t  *sim_ndef_file; /* Type 4: NDEF file, NLEN first */
    size_t          sim_ndef_file_len;
    const uint8_t  *sim_file; /* Type 4: selected file */
    size_t          sim_file_len;
};

static const uint8_t ack_frame[]  = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
static const uint8_t nack_frame[] = {0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00};

static bool mock_write(pn532_bus_t *bus, const uint8_t *buffer, size_t len)
{
    mock_bus_t *mock = (mock_bus_t *)bus;

    if (len == sizeof(ack_frame) && memcmp(buffer, ack_frame, sizeof(ack_frame)) == 0) {
        mock->abort_count++;
        /* The abort ACK is not a command: the drain that follows reads data
         * frames directly, so skip the ACK-phase length assert. */
        mock->read_phase = 1;
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

    if (command == PN532_COMMAND_SETPARAMETERS) {
        mock->tama_params = buffer[7];
    }

    /* Short frame layout: preamble(3) LEN ~LEN TF CMD then params. Capture the
     * InitiatorData of targeted InListPassiveTarget calls so tests can verify
     * cascade-tag insertion without real hardware. */
    if (command == PN532_COMMAND_INLISTPASSIVETARGET) {
        size_t params_len = (buffer[3] == 0xFF) ? (((size_t)buffer[5] << 8) | buffer[6]) : (size_t)buffer[3];
        params_len -= 2u; /* payload = TF + CMD */
        if (params_len > 2u) {
            size_t initiator_len = params_len - 2u; /* MaxTg + BrTy */
            /* Short frame: preamble(3) LEN ~LEN TF CMD MaxTg BrTy data...;
             * extended frame adds the two length bytes and their checksum. */
            const uint8_t *initiator = (buffer[3] == 0xFF) ? &buffer[10] : &buffer[9];
            TEST_ASSERT_LESS_OR_EQUAL(sizeof(mock->list_initiator), initiator_len);
            memcpy(mock->list_initiator, initiator, initiator_len);
            mock->list_initiator_len   = initiator_len;
            mock->list_initiator_valid = true;
        }
    }

    /* Capture the full request parameters of each InDataExchange /
     * InCommunicateThru round so tests can assert what the MI continuation
     * re-sends (UM0701-02 §7.3.5: only the target number). Frames larger
     * than the capture slot (frame-size tests) and rounds beyond the first
     * few (MI loop tests) are counted but not stored. */
    if (command == PN532_COMMAND_INDATAEXCHANGE || command == PN532_COMMAND_INCOMMUNICATETHRU) {
        size_t params_len = (buffer[3] == 0xFF) ? (((size_t)buffer[5] << 8) | buffer[6]) : (size_t)buffer[3];
        params_len -= 2u; /* payload = TF + CMD */
        const uint8_t *params = (buffer[3] == 0xFF) ? &buffer[10] : &buffer[7];
        if (mock->exchange_rounds < ARRAY_SIZE(mock->exchange_params) &&
            params_len <= sizeof(mock->exchange_params[0])) {
            memcpy(mock->exchange_params[mock->exchange_rounds], params, params_len);
            mock->exchange_params_len[mock->exchange_rounds] = params_len;
        }
        mock->exchange_rounds++;
        mock->sim_request_len = params_len < sizeof(mock->sim_request) ? params_len : sizeof(mock->sim_request);
        memcpy(mock->sim_request, params, mock->sim_request_len);
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
    case PN532_COMMAND_SETPARAMETERS:
    case PN532_COMMAND_SAMCONFIGURATION:
        /* UM0701-02 §7.2.10: the SAMConfiguration response carries no data. */
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
        if (mock->mode == MOCK_CARD && mock->card_sak != 0) {
            /* Same card with another SAK. Like the chip, append an ATS only
             * for an ISO14443-4 SAK while automatic RATS (0x10) is on. */
            static uint8_t     custom[sizeof(card) + 5];
            static const uint8_t ats[] = {0x05, 0x78, 0x80, 0x70, 0x02};
            bool               rats    = mock->tama_params == 0 || (mock->tama_params & 0x10) != 0;
            memcpy(custom, card, sizeof(card));
            custom[4]   = mock->card_sak;
            payload     = custom;
            payload_len = sizeof(card);
            if ((mock->card_sak & 0x20) != 0 && rats) {
                memcpy(custom + sizeof(card), ats, sizeof(ats));
                payload_len += sizeof(ats);
            }
        }
        if (mock->mode == MOCK_TWO_LONG_ATS) {
            /* NbTg=2; each: Tg ATQA(2) SAK=0x20 UIDLen=7 UID(7) ATS(TL=30): 85 bytes total. */
            static uint8_t two_ats[1 + 2 * 42];
            two_ats[0] = 2;
            for (uint8_t t = 0; t < 2; t++) {
                uint8_t *e = &two_ats[1 + t * 42];
                e[0]       = (uint8_t)(t + 1);
                e[1]       = 0x44;
                e[2]       = 0x03;
                e[3]       = mock->two_ats_sak[t] != 0 ? mock->two_ats_sak[t] : 0x20;
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

    if (mock->mode == MOCK_SIM_CARD && (mock->current_command == PN532_COMMAND_INDATAEXCHANGE ||
                                        mock->current_command == PN532_COMMAND_INCOMMUNICATETHRU)) {
        uint8_t sim_response[1 + 256];
        size_t  sim_len =
            mock->sim_card(mock, mock->current_command, mock->sim_request, mock->sim_request_len, sim_response);
        mock_response_frame(mock->current_command, sim_response, sim_len, buffer, len);
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

    if (mock->mode == MOCK_TYPE4_SELECT_V1 && mock->current_command == PN532_COMMAND_INDATAEXCHANGE) {
        /* Mapping 1.0 style card: SELECT with P2=0x0C is refused with 6A86,
         * any other APDU succeeds. Request params: Tg CLA INS P1 P2 ... */
        static const uint8_t refused[]  = {0x00, 0x6A, 0x86};
        static const uint8_t accepted[] = {0x00, 0x90, 0x00};
        const uint8_t       *request    = mock->exchange_params[mock->exchange_rounds - 1];
        bool                 is_v2      = request[2] == 0xA4 && request[4] == 0x0C;
        mock_response_frame(mock->current_command, is_v2 ? refused : accepted, 3, buffer, len);
        return true;
    }

    if (mock->mode == MOCK_AUTH_ERROR && mock->current_command == PN532_COMMAND_INDATAEXCHANGE) {
        /* UM0701: 0x14 = MIFARE authentication error. */
        static const uint8_t auth_error[] = {0x14};
        mock_response_frame(mock->current_command, auth_error, sizeof(auth_error), buffer, len);
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

    /* A well-formed frame refusing the command while the transport itself is
     * healthy: exercises the protocol-error mapping of the poll path. */
    if (mock->mode == MOCK_RELEASE_PROTOCOL_ERROR && mock->current_command == PN532_COMMAND_INRELEASE) {
        static const uint8_t refused[] = {0x29};
        mock_response_frame(mock->current_command, refused, sizeof(refused), buffer, len);
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
                                PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_SETPARAMETERS,
                                PN532_COMMAND_RFCONFIGURATION};
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

    /* UM0701-02 §7.3.5: round 0 sends the target number plus the caller's
     * data; the MI continuation must carry the target number only, so the
     * APDU is not forwarded to the card twice. */
    TEST_ASSERT_EQUAL(2, mock.exchange_rounds);
    TEST_ASSERT_EQUAL(3, mock.exchange_params_len[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0x01, 0x30, 0x00}), mock.exchange_params[0], 3);
    TEST_ASSERT_EQUAL(1, mock.exchange_params_len[1]);
    TEST_ASSERT_EQUAL_UINT8(0x01, mock.exchange_params[1][0]);

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

    /* Round 0 carries the raw bits; the MI continuation re-sends nothing. */
    TEST_ASSERT_EQUAL(2, mock.exchange_rounds);
    TEST_ASSERT_EQUAL(2, mock.exchange_params_len[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(((const uint8_t[]){0xE0, 0x80}), mock.exchange_params[0], 2);
    TEST_ASSERT_EQUAL(0, mock.exchange_params_len[1]);

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

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_parse_message(encoded, sizeof(encoded), &message));
    TEST_ASSERT_NOT_NULL(message);
    TEST_ASSERT_EQUAL(1, message->record_count);
    TEST_ASSERT_EQUAL(PN532_NDEF_TNF_WELL_KNOWN, message->records[0].tnf);
    TEST_ASSERT_EQUAL_UINT8('T', message->records[0].type[0]);
    TEST_ASSERT_EQUAL(5, message->records[0].payload_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("hello", message->records[0].payload, 5);
    pn532_ndef_free_parsed_message(message);
}

TEST_CASE("NDEF chunk sequence can precede another record", "[pn532][ndef][chunk]")
{
    static const uint8_t encoded[] = {
        0xB1, 0x01, 0x02, 'T', 'h',  'e', /* MB | CF | SR, first chunk */
        0x36, 0x00, 0x02, 'l', 'l',       /* CF | SR, middle chunk */
        0x16, 0x00, 0x01, 'o',            /* SR, final chunk */
        0x51, 0x01, 0x02, 'U', 0x00, 'x'  /* ME | SR, normal record */
    };

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_parse_message(encoded, sizeof(encoded), &message));
    TEST_ASSERT_EQUAL(2, message->record_count);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("hello", message->records[0].payload, 5);
    TEST_ASSERT_EQUAL_UINT8('U', message->records[1].type[0]);
    TEST_ASSERT_EQUAL(2, message->records[1].payload_len);
    pn532_ndef_free_parsed_message(message);
}

TEST_CASE("NDEF orphan continuation chunk is rejected", "[pn532][ndef][chunk]")
{
    static const uint8_t encoded[] = {
        0xD6, 0x00, 0x01, 'x', /* MB | ME | SR, TNF_UNCHANGED without first chunk */
    };

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_ERR_PARSE_FAILED, pn532_ndef_parse_message(encoded, sizeof(encoded), &message));
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

#ifndef PN532_HOST_TEST /* needs the UART transport, which the host build leaves out */
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
#endif

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

TEST_CASE("reserved TNF is rejected by NDEF parsing", "[pn532][ndef][tnf]")
{
    static const uint8_t encoded[] = {
        0xD7, 0x01, 0x01, 'U', 0x00, 'x', /* MB | ME | SR with TNF 0x07 (reserved) */
    };

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_ERR_PARSE_FAILED, pn532_ndef_parse_message(encoded, sizeof(encoded), &message));
    TEST_ASSERT_NULL(message);
}

TEST_CASE("empty TNF record with payload or type is rejected", "[pn532][ndef][tnf]")
{
    /* TNF=0 with a type byte: structurally illegal per NFC RTD. */
    static const uint8_t bad_type[] = {
        0xD0, 0x01, 0x00, 'T', /* MB | ME | SR, TNF_EMPTY with a type */
    };
    /* TNF=0 with a payload byte. */
    static const uint8_t bad_payload[] = {
        0xD0, 0x00, 0x01, 'x', /* MB | ME | SR, TNF_EMPTY with a payload */
    };
    /* The only legal empty record: no type, no ID, no payload. */
    static const uint8_t ok[] = {
        0xD0, 0x00, 0x00, /* MB | ME | SR, TNF_EMPTY, fully empty */
    };

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_ERR_PARSE_FAILED, pn532_ndef_parse_message(bad_type, sizeof(bad_type), &message));
    TEST_ASSERT_NULL(message);
    TEST_ASSERT_EQUAL(PN532_NDEF_ERR_PARSE_FAILED,
                      pn532_ndef_parse_message(bad_payload, sizeof(bad_payload), &message));
    TEST_ASSERT_NULL(message);
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_parse_message(ok, sizeof(ok), &message));
    TEST_ASSERT_EQUAL(1, message->record_count);
    TEST_ASSERT_EQUAL(PN532_NDEF_TNF_EMPTY, message->records[0].tnf);
    pn532_ndef_free_parsed_message(message);
}

TEST_CASE("URI identifier 0x07 decodes and encodes the anonymous FTP prefix", "[pn532][ndef][uri]")
{
    /* Decoding: identifier 0x07 + "example.com" must expand to the full
     * ftp://anonymous:anonymous@ prefix, not the old placeholder. */
    static const uint8_t encoded[] = {
        0xD1, 0x01, 0x0C, 'U', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
    };

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_parse_message(encoded, sizeof(encoded), &message));
    TEST_ASSERT_NOT_NULL(message);
    TEST_ASSERT_TRUE(pn532_ndef_record_is_uri(&message->records[0]));

    char uri[64];
    TEST_ASSERT_EQUAL(37, pn532_ndef_extract_uri(&message->records[0], uri, sizeof(uri)));
    TEST_ASSERT_EQUAL_STRING("ftp://anonymous:anonymous@example.com", uri);
    pn532_ndef_free_parsed_message(message);

    /* Encoding: the full prefix must compress back to identifier 0x07. */
    pn532_ndef_record_t rec;
    uint8_t       payload_buf[16];
    TEST_ASSERT_TRUE(pn532_ndef_make_uri_record(&rec, "ftp://anonymous:anonymous@example.com", true, payload_buf,
                                                sizeof(payload_buf)));
    /* Encoded payload = 0x07 identifier + "example.com" (11 chars). */
    TEST_ASSERT_EQUAL(12, rec.payload_len);
    TEST_ASSERT_EQUAL_UINT8(0x07, rec.payload[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY("example.com", rec.payload + 1, 11);
}

TEST_CASE("READ BINARY rejects offsets above the short-file limit", "[pn532][t4][readbinary]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_TYPE4_APDU, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    uint8_t buf[16];
    size_t  got = sizeof(buf);
    /* Must fail before any transport traffic: the offset does not fit the
     * short EF identifier encoding (P1 b8 must stay 0). */
    TEST_ASSERT_FALSE(pn532_14443_4_read_binary(&pn532, 0x8000, sizeof(buf), buf, &got));
    TEST_ASSERT_EQUAL(0, mock.command_count);

    got = sizeof(buf);
    TEST_ASSERT_FALSE(pn532_14443_4_read_binary(&pn532, 0xFFFF, sizeof(buf), buf, &got));
    TEST_ASSERT_EQUAL(0, mock.command_count);
}

TEST_CASE("READ BINARY reports required size instead of truncating", "[pn532][t4][readbinary]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_TYPE4_APDU, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    /* MOCK_TYPE4_APDU returns 3 data bytes + SW after the exchange status is
     * stripped. A 2-byte buffer cannot hold the reply; the call must fail and
     * report 3 as the required size. */
    uint8_t buf[2];
    size_t  got = sizeof(buf);
    TEST_ASSERT_FALSE(pn532_14443_4_read_binary(&pn532, 0, sizeof(buf), buf, &got));
    TEST_ASSERT_EQUAL(3, got);
}

TEST_CASE("protocol-level poll failure maps to PN532_POLL_PROTOCOL_ERROR", "[pn532][polling][protocol]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_RELEASE_PROTOCOL_ERROR, send_buf, recv_buf);
    pn532.inListedTag = 1;

    /* Release fails with a well-formed 0x29 frame while the transport is
     * healthy: the poll must surface a protocol error, not a transport
     * error that would trigger needless pn532_recover() calls. */
    pn532_poll_status_t status;
    pn532_uids_array_t *uids = pn532_14443_get_all_uids_ex(&pn532, &status);
    TEST_ASSERT_EQUAL(PN532_POLL_PROTOCOL_ERROR, status);
    TEST_ASSERT_NULL(uids);
}

TEST_CASE("ATS follows every SAK with the ISO14443-4 bit, ATQA keeps the reported byte order",
          "[pn532][polling][ats]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_TWO_LONG_ATS, send_buf, recv_buf);
    /* Classic emulation on an ISO-DEP card, and ISO-DEP + NFC-DEP: the PN532
     * appends the ATS to both, so the second entry starts after it. */
    mock.two_ats_sak[0] = 0x28;
    mock.two_ats_sak[1] = 0x60;

    pn532_poll_status_t status;
    pn532_uids_array_t *uids = pn532_14443_get_all_uids_ex(&pn532, &status);
    TEST_ASSERT_EQUAL(PN532_POLL_FOUND, status);
    TEST_ASSERT_NOT_NULL(uids);
    TEST_ASSERT_EQUAL(2, uids->uids_count);
    TEST_ASSERT_EQUAL_UINT8(0x28, uids->uids[0].sak);
    TEST_ASSERT_EQUAL_UINT8(0x60, uids->uids[1].sak);
    TEST_ASSERT_EQUAL_UINT8(2, uids->uids[1].tg);
    TEST_ASSERT_EQUAL(7, uids->uids[1].uid_length);
    TEST_ASSERT_EACH_EQUAL_UINT8(0x11, uids->uids[1].uid, 7);
    /* SENS_RES bytes 0x44 0x03 as reported by the PN532. */
    TEST_ASSERT_EQUAL_HEX16(0x4403, uids->uids[0].atqa);
    free(uids);
}

TEST_CASE("Classic emulation on an ISO-DEP card is re-listed without automatic RATS", "[pn532][polling][rats]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    mock.card_sak = 0x28;

    /* Discovery runs with the chip default (automatic RATS on): no
     * SetParameters is needed and the ATS behind the UID is skipped. */
    pn532_uids_array_t *uids = pn532_14443_get_all_uids(&pn532);
    TEST_ASSERT_NOT_NULL(uids);
    TEST_ASSERT_EQUAL(1, uids->uids_count);
    TEST_ASSERT_EQUAL(PN532_MIFARE_CLASSIC_1K, uids->uids[0].subtype);
    const uint8_t poll[] = {PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_INLISTPASSIVETARGET};
    assert_commands(&mock, poll, ARRAY_SIZE(poll));

    /* The poll activated the card as ISO-DEP, so its Tg is not reused:
     * field off, RATS off, targeted list, select. */
    mock.command_count = 0;
    TEST_ASSERT_TRUE(pn532_14443_select_by_uid(&pn532, &uids->uids[0]));
    const uint8_t select[] = {PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_SETPARAMETERS,
                              PN532_COMMAND_INLISTPASSIVETARGET, PN532_COMMAND_INSELECT};
    assert_commands(&mock, select, ARRAY_SIZE(select));
    TEST_ASSERT_EQUAL_HEX8(0x04, mock.tama_params);
    TEST_ASSERT_TRUE(pn532.auto_rats_off);
    TEST_ASSERT_TRUE(pn532.session_opened);

    /* A second select of the same card finds it listed in the right mode. */
    pn532_uid_t listed = uids->uids[0];
    listed.tg          = pn532.inListedTag;
    mock.command_count = 0;
    TEST_ASSERT_TRUE(pn532_14443_select_by_uid(&pn532, &listed));
    const uint8_t reselect[] = {PN532_COMMAND_INSELECT};
    assert_commands(&mock, reselect, ARRAY_SIZE(reselect));
    free(uids);

    /* Overriding the subtype asks for the ISO-DEP side of the same card: it
     * is listed in the wrong mode now, so RATS goes back on and it is
     * re-listed. */
    pn532_uid_t iso_dep = listed;
    iso_dep.subtype     = PN532_MIFARE_DESFIRE;
    mock.command_count  = 0;
    TEST_ASSERT_TRUE(pn532_14443_select_by_uid(&pn532, &iso_dep));
    assert_commands(&mock, select, ARRAY_SIZE(select));
    TEST_ASSERT_EQUAL_HEX8(0x14, mock.tama_params);
    TEST_ASSERT_FALSE(pn532.auto_rats_off);

    /* Back to the Classic side for the rest of the test. */
    TEST_ASSERT_TRUE(pn532_14443_select_by_uid(&pn532, &listed));
    TEST_ASSERT_TRUE(pn532.auto_rats_off);

    /* The next poll restores automatic RATS before listing. */
    mock.command_count = 0;
    uids               = pn532_14443_get_all_uids(&pn532);
    TEST_ASSERT_NOT_NULL(uids);
    const uint8_t repoll[] = {PN532_COMMAND_INRELEASE, PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_SETPARAMETERS,
                              PN532_COMMAND_INLISTPASSIVETARGET};
    assert_commands(&mock, repoll, ARRAY_SIZE(repoll));
    TEST_ASSERT_EQUAL_HEX8(0x14, mock.tama_params);
    TEST_ASSERT_FALSE(pn532.auto_rats_off);
    free(uids);
}

TEST_CASE("unknown TNF record with a type is rejected", "[pn532][ndef][tnf]")
{
    static const uint8_t with_type[] = {0xD5, 0x01, 0x01, 'x', 0xAA};
    static const uint8_t no_type[]   = {0xD5, 0x00, 0x01, 0xAA};

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_ERR_PARSE_FAILED, pn532_ndef_parse_message(with_type, sizeof(with_type), &message));
    TEST_ASSERT_NULL(message);
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_parse_message(no_type, sizeof(no_type), &message));
    TEST_ASSERT_EQUAL(PN532_NDEF_TNF_UNKNOWN, message->records[0].tnf);
    pn532_ndef_free_parsed_message(message);
}

TEST_CASE("NDEF record length that wraps the offset is rejected", "[pn532][ndef][bounds]")
{
    /* Long record whose payload length 0xFFFFFFFF wraps a 32-bit offset back
     * onto its own type byte ('T' = 0x54 = ME|SR|TNF 4), which then parses as
     * a closing record. Must not yield a 4 GiB Text record. */
    static const uint8_t wrapping[] = {0x81, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x00, 0x00};

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_ERR_PARSE_FAILED, pn532_ndef_parse_message(wrapping, sizeof(wrapping), &message));
    TEST_ASSERT_NULL(message);
}

static void assert_uri_round_trip(const char *uri, uint8_t expected_code)
{
    pn532_ndef_record_t rec;
    uint8_t       payload_buf[64];
    char          decoded[64];

    TEST_ASSERT_TRUE(pn532_ndef_make_uri_record(&rec, uri, true, payload_buf, sizeof(payload_buf)));
    TEST_ASSERT_EQUAL_HEX8(expected_code, rec.payload[0]);
    TEST_ASSERT_EQUAL(strlen(uri), pn532_ndef_extract_uri(&rec, decoded, sizeof(decoded)));
    TEST_ASSERT_EQUAL_STRING(uri, decoded);
}

TEST_CASE("URI identifier codes follow the NFC Forum URI RTD table", "[pn532][ndef][uri]")
{
    /* Decoding a foreign tag: 0x13 is "urn:", 0x1D is "file://". */
    static const uint8_t urn[]  = {0xD1, 0x01, 0x07, 'U', 0x13, 'i', 's', 'b', 'n', ':', '1'};
    static const uint8_t file[] = {0xD1, 0x01, 0x03, 'U', 0x1D, '/', 'a'};
    char                 uri[32];

    pn532_ndef_message_parsed_t *message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_parse_message(urn, sizeof(urn), &message));
    TEST_ASSERT_EQUAL(10, pn532_ndef_extract_uri(&message->records[0], uri, sizeof(uri)));
    TEST_ASSERT_EQUAL_STRING("urn:isbn:1", uri);
    pn532_ndef_free_parsed_message(message);

    message = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_parse_message(file, sizeof(file), &message));
    TEST_ASSERT_EQUAL(9, pn532_ndef_extract_uri(&message->records[0], uri, sizeof(uri)));
    TEST_ASSERT_EQUAL_STRING("file:///a", uri);
    pn532_ndef_free_parsed_message(message);

    /* Encoding picks the longest standard prefix and round-trips. */
    assert_uri_round_trip("ftp://ftp.example.com/a", 0x08);
    assert_uri_round_trip("ftp://ftpserver.com/a", 0x0D);
    assert_uri_round_trip("urn:isbn:1", 0x13);
    assert_uri_round_trip("urn:epc:id:sgtin:1", 0x1E);
    assert_uri_round_trip("urn:epc:other", 0x22);
    assert_uri_round_trip("https://www.example.com", 0x02);
    /* Schemes without a standard code stay unabbreviated. */
    assert_uri_round_trip("geo:1,2", 0x00);
    assert_uri_round_trip("sms:+123", 0x00);
}

TEST_CASE("Type 4 file select uses P2=0x0C and falls back to P2=0x00", "[pn532][t4][select]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    static const uint8_t cc_file_id[]       = {0xE1, 0x03};
    static const uint8_t ndef_aid[]         = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};

    mock_init(&mock, &pn532, MOCK_TYPE4_APDU, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    TEST_ASSERT_TRUE(pn532_14443_4_select_file(&pn532, cc_file_id, sizeof(cc_file_id)));
    TEST_ASSERT_EQUAL(1, mock.exchange_rounds);
    const uint8_t by_fid[] = {0x01, 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03};
    TEST_ASSERT_EQUAL(sizeof(by_fid), mock.exchange_params_len[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(by_fid, mock.exchange_params[0], sizeof(by_fid));

    TEST_ASSERT_TRUE(pn532_14443_4_select_file(&pn532, ndef_aid, sizeof(ndef_aid)));
    TEST_ASSERT_EQUAL(2, mock.exchange_rounds);
    const uint8_t by_aid[] = {0x01, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    TEST_ASSERT_EQUAL(sizeof(by_aid), mock.exchange_params_len[1]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(by_aid, mock.exchange_params[1], sizeof(by_aid));

    /* A card that refuses P2=0x0C gets one retry with P2=0x00. */
    mock_init(&mock, &pn532, MOCK_TYPE4_SELECT_V1, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;

    TEST_ASSERT_TRUE(pn532_14443_4_select_file(&pn532, cc_file_id, sizeof(cc_file_id)));
    TEST_ASSERT_EQUAL(2, mock.exchange_rounds);
    TEST_ASSERT_EQUAL_HEX8(0x0C, mock.exchange_params[0][4]);
    TEST_ASSERT_EQUAL_HEX8(0x00, mock.exchange_params[1][4]);
}

TEST_CASE("failed MIFARE authentication forces a full re-list on the next select", "[pn532][polling][auth]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_AUTH_ERROR, send_buf, recv_buf);
    pn532.inListedTag    = 1;
    pn532.session_opened = true;
    pn532.is_rf_on       = true;

    pn532_uid_t uid = {.uid = {0xDE, 0xAD, 0xBE, 0xEF}, .uid_length = 4, .tg = 1, .subtype = PN532_MIFARE_CLASSIC_1K};
    static const uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    TEST_ASSERT_FALSE(pn532_14443_authenticate(&pn532, key, PN532_MIFARE_CMD_AUTH_A, &uid, 4));
    TEST_ASSERT_TRUE(pn532.tg_stale);
    TEST_ASSERT_FALSE(pn532.session_opened);
    TEST_ASSERT_EQUAL_UINT8(1, pn532.inListedTag);

    /* The card is back in IDLE while the PN532 still counts it as selected:
     * the cached Tg must not be reused through a bare InSelect. */
    mock.command_count = 0;
    TEST_ASSERT_TRUE(pn532_14443_select_by_uid(&pn532, &uid));
    const uint8_t expected[] = {PN532_COMMAND_RFCONFIGURATION, PN532_COMMAND_INLISTPASSIVETARGET,
                                PN532_COMMAND_INSELECT};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
    TEST_ASSERT_FALSE(pn532.tg_stale);
    TEST_ASSERT_TRUE(pn532.session_opened);
}

TEST_CASE("a Tg that now belongs to another card is not reused", "[pn532][polling][tg]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);

    pn532_uids_array_t *uids = pn532_14443_get_all_uids(&pn532);
    TEST_ASSERT_NOT_NULL(uids);
    TEST_ASSERT_EQUAL_UINT8(1, uids->uids[0].tg);

    /* A descriptor kept from an earlier poll: same Tg, another card. A bare
     * InSelect would open the card in the field under the old card's name. */
    pn532_uid_t removed = uids->uids[0];
    removed.uid[0] ^= 0xFF;
    mock.command_count = 0;
    TEST_ASSERT_FALSE(pn532_14443_select_by_uid(&pn532, &removed));
    TEST_ASSERT_TRUE(mock.command_count > 0);
    for (size_t i = 0; i < mock.command_count; i++) {
        TEST_ASSERT_NOT_EQUAL(PN532_COMMAND_INSELECT, mock.commands[i]);
    }
    TEST_ASSERT_EQUAL_UINT8(0, pn532.inListedTag);

    /* The card that is in the field still takes the short path after a new poll. */
    free(uids);
    uids = pn532_14443_get_all_uids(&pn532);
    TEST_ASSERT_NOT_NULL(uids);
    mock.command_count = 0;
    TEST_ASSERT_TRUE(pn532_14443_select_by_uid(&pn532, &uids->uids[0]));
    const uint8_t expected[] = {PN532_COMMAND_INSELECT};
    assert_commands(&mock, expected, ARRAY_SIZE(expected));
    free(uids);
}

TEST_CASE("NULL device pointers are rejected without crashing", "[pn532][args]")
{
    TEST_ASSERT_EQUAL_UINT32(0, pn532_get_firmware_version(NULL));
    TEST_ASSERT_FALSE(pn532_set_rf_field(NULL, true));
    TEST_ASSERT_FALSE(pn532_execute_command(NULL, PN532_COMMAND_GETFIRMWAREVERSION, NULL, 0, NULL, NULL, 10));
    TEST_ASSERT_FALSE(pn532_reset(NULL));
    TEST_ASSERT_FALSE(pn532_in_data_exchange(NULL, (const uint8_t *)"\x30\x00", 2, NULL, NULL, 10));

    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    mock_init(&mock, &pn532, MOCK_CARD, send_buf, recv_buf);
    pn532.inListedTag = 1;

    /* Out-of-range block numbers must fail instead of wrapping (256 -> 0
     * would read the manufacturer block). */
    uint8_t block[16];
    TEST_ASSERT_FALSE(pn532_mifare_block_read(&pn532, 256, block, sizeof(block)));
    TEST_ASSERT_FALSE(pn532_mifare_block_read(&pn532, -1, block, sizeof(block)));
    TEST_ASSERT_EQUAL(-1, pn532_mifare_block_write(&pn532, 300, block, 16));
    TEST_ASSERT_EQUAL(0, mock.command_count);
}

/* ---- Simulated cards (MOCK_SIM_CARD) ---- */

/* UM0701-02: 0x01 = RF timeout (the card stays silent), 0x13 = framing error. */
#define SIM_STATUS_TIMEOUT 0x01

/* Type 2 tag: READ through InDataExchange, GET_VERSION / AUTHENTICATE through InCommunicateThru. */
static size_t sim_type2_card(mock_bus_t *mock, uint8_t command, const uint8_t *request, size_t request_len,
                             uint8_t *response)
{
    response[0] = SIM_STATUS_TIMEOUT;
    if (command == PN532_COMMAND_INCOMMUNICATETHRU) {
        if (request_len == 1 && request[0] == 0x60 && mock->sim_version != NULL) {
            response[0] = 0x00;
            memcpy(&response[1], mock->sim_version, 8);
            return 9;
        }
        if (request_len == 2 && request[0] == 0x1A && mock->sim_ulc) {
            response[0] = 0x00;
            response[1] = 0xAF;
            memset(&response[2], 0x5A, 8);
            return 10;
        }
        return 1;
    }
    if (request_len == 3 && request[1] == PN532_MIFARE_CMD_READ && request[2] < mock->sim_units) {
        /* Four pages, wrapping around to page 0 at the end of the memory. */
        response[0] = 0x00;
        for (size_t i = 0; i < 4; i++) {
            size_t page = (request[2] + i) % mock->sim_units;
            memcpy(&response[1 + i * 4], &mock->sim_memory[page * 4], 4);
        }
        mock->sim_reads++;
        return 17;
    }
    return 1;
}

/* MIFARE Classic: every authentication succeeds, READ returns one block. */
static size_t sim_classic_card(mock_bus_t *mock, uint8_t command, const uint8_t *request, size_t request_len,
                               uint8_t *response)
{
    (void)command;
    response[0] = SIM_STATUS_TIMEOUT;
    if (request_len >= 3 && (request[1] == PN532_MIFARE_CMD_AUTH_A || request[1] == PN532_MIFARE_CMD_AUTH_B)) {
        response[0] = 0x00;
        return 1;
    }
    if (request_len == 3 && request[1] == PN532_MIFARE_CMD_READ && request[2] < mock->sim_units) {
        response[0] = 0x00;
        memcpy(&response[1], &mock->sim_memory[(size_t)request[2] * 16], 16);
        mock->sim_reads++;
        return 17;
    }
    return 1;
}

/* Type 4 tag: NDEF application with a capability container file and one NDEF file. */
static size_t sim_type4_card(mock_bus_t *mock, uint8_t command, const uint8_t *request, size_t request_len,
                             uint8_t *response)
{
    (void)command;
    const uint8_t *apdu     = request + 1; /* skip Tg */
    size_t         apdu_len = request_len - 1;
    size_t         out      = 1;

    response[0] = 0x00;
    if (apdu_len >= 5 && apdu[1] == 0xA4) {
        bool ok = false;
        if (apdu[2] == 0x04) {
            ok = true; /* by AID */
        } else if (apdu_len >= 7 && apdu[5] == 0xE1 && apdu[6] == 0x03) {
            mock->sim_file     = mock->sim_cc_file;
            mock->sim_file_len = 15;
            ok                 = true;
        } else if (apdu_len >= 7 && apdu[5] == mock->sim_cc_file[9] && apdu[6] == mock->sim_cc_file[10]) {
            mock->sim_file     = mock->sim_ndef_file;
            mock->sim_file_len = mock->sim_ndef_file_len;
            ok                 = true;
        }
        response[out++] = ok ? 0x90 : 0x6A;
        response[out++] = ok ? 0x00 : 0x82;
        return out;
    }
    if (apdu_len == 5 && apdu[1] == 0xB0 && mock->sim_file != NULL) {
        size_t offset = ((size_t)apdu[2] << 8) | apdu[3];
        size_t le     = apdu[4];
        if (offset + le <= mock->sim_file_len) {
            memcpy(&response[out], mock->sim_file + offset, le);
            out += le;
            mock->sim_reads++;
            response[out++] = 0x90;
            response[out++] = 0x00;
            return out;
        }
    }
    response[out++] = 0x6A;
    response[out++] = 0x86;
    return out;
}

/* Starts a test on a simulated card that is already listed and selected as Tg 1. */
static void sim_init(mock_bus_t *mock, pn532_t *pn532, mock_sim_card_t card, uint8_t *send_buf, uint8_t *recv_buf)
{
    mock_init(mock, pn532, MOCK_SIM_CARD, send_buf, recv_buf);
    mock->sim_card        = card;
    pn532->inListedTag    = 1;
    pn532->session_opened = true;
    pn532->is_rf_on       = true;
}

/* NDEF message with one Text record "a". */
static const uint8_t sim_ndef_text[] = {0xD1, 0x01, 0x04, 'T', 0x02, 'e', 'n', 'a'};

TEST_CASE("an unlisted SAK with the ISO14443-4 bit is an ISO-DEP card", "[pn532][polling][sak]")
{
    uint16_t blocks     = UINT16_MAX;
    uint16_t block_size = UINT16_MAX;

    pn532_uid_t iso_dep = {.sak = 0x60};
    TEST_ASSERT_TRUE(pn532_14443_detect_card_type_and_capacity(&iso_dep, &blocks, &block_size));
    TEST_ASSERT_EQUAL(PN532_MIFARE_DESFIRE, iso_dep.subtype);
    TEST_ASSERT_EQUAL_UINT16(0, blocks);
    TEST_ASSERT_EQUAL_UINT16(1, block_size);

    pn532_uid_t unknown = {.sak = 0x40};
    TEST_ASSERT_TRUE(pn532_14443_detect_card_type_and_capacity(&unknown, &blocks, &block_size));
    TEST_ASSERT_EQUAL(PN532_MIFARE_UNKNOWN, unknown.subtype);
    TEST_ASSERT_EQUAL_UINT16(0, blocks);
    TEST_ASSERT_EQUAL_UINT16(0, block_size);
}

TEST_CASE("Type 2 tag without a capability container is not scanned", "[pn532][ndef][t2]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    memory[16 * 4]               = {0};

    /* An NDEF TLV in the data area, but no CC magic in page 3. */
    memory[16] = 0x03;
    memory[17] = sizeof(sim_ndef_text);
    memcpy(&memory[18], sim_ndef_text, sizeof(sim_ndef_text));

    for (int variant = 0; variant < 2; variant++) {
        sim_init(&mock, &pn532, sim_type2_card, send_buf, recv_buf);
        mock.sim_memory = memory;
        mock.sim_units  = 16;
        if (variant == 1) {
            /* CC magic present, but an empty data area. */
            memory[12] = 0xE1;
            memory[13] = 0x10;
            memory[14] = 0x00;
        }

        pn532_uid_t uid = {
            .uid          = {0xDE, 0xAD, 0xBE, 0xEF},
            .uid_length   = 4,
            .tg           = 1,
            .sak          = 0x00,
            .subtype      = PN532_MIFARE_ULTRALIGHT,
            .block_size   = 4,
            .blocks_count = 16
        };
        pn532_ndef_message_parsed_t *msg = NULL;
        TEST_ASSERT_EQUAL(PN532_NDEF_ERR_NO_NDEF, pn532_ndef_read_card_auto(&pn532, &uid, &msg));
        TEST_ASSERT_NULL(msg);
        TEST_ASSERT_EQUAL(1, mock.sim_reads);
    }
}

TEST_CASE("Type 2 NDEF read stays inside the data area", "[pn532][ndef][t2]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    memory[16 * 4]               = {0};

    /* CC: 40 bytes of data area, pages 4..13. Pages 14 and 15 are outside it
     * and hold bytes that look like an NDEF TLV; the last READ (page 12)
     * returns them, and they must not be taken for a message. */
    memory[12] = 0xE1;
    memory[13] = 0x10;
    memory[14] = 0x05;
    memory[56] = 0x03;
    memory[57] = sizeof(sim_ndef_text);
    memcpy(&memory[58], sim_ndef_text, 6);

    sim_init(&mock, &pn532, sim_type2_card, send_buf, recv_buf);
    mock.sim_memory = memory;
    mock.sim_units  = 16;

    pn532_uid_t uid = {
        .uid          = {0xDE, 0xAD, 0xBE, 0xEF},
        .uid_length   = 4,
        .tg           = 1,
        .sak          = 0x00,
        .subtype      = PN532_MIFARE_ULTRALIGHT,
        .block_size   = 4,
        .blocks_count = 16
    };
    pn532_ndef_message_parsed_t *msg = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_ERR_NO_NDEF, pn532_ndef_read_card_auto(&pn532, &uid, &msg));
    TEST_ASSERT_NULL(msg);
    TEST_ASSERT_EQUAL_UINT16(14, uid.blocks_count);

    /* The same TLV inside the data area is read. */
    memset(&memory[56], 0, 8);
    memory[16] = 0x03;
    memory[17] = sizeof(sim_ndef_text);
    memcpy(&memory[18], sim_ndef_text, sizeof(sim_ndef_text));
    memory[18 + sizeof(sim_ndef_text)] = 0xFE;

    sim_init(&mock, &pn532, sim_type2_card, send_buf, recv_buf);
    mock.sim_memory = memory;
    mock.sim_units  = 16;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_read_card_auto(&pn532, &uid, &msg));
    TEST_ASSERT_NOT_NULL(msg);
    TEST_ASSERT_EQUAL(1, msg->record_count);
    TEST_ASSERT_TRUE(pn532_ndef_record_is_text(&msg->records[0]));
    pn532_ndef_free_parsed_message(msg);
}

TEST_CASE("Ultralight family members are told apart on the selected card", "[pn532][polling][ultralight]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    uint16_t   blocks                       = 0;
    uint16_t   block_size                   = 0;
    bool       needs_reselect               = true;

    static const uint8_t ntag215[]  = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03};
    static const uint8_t ntag210[]  = {0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x0B, 0x03};
    static const uint8_t ul_ev1[]   = {0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0B, 0x03};
    const pn532_uid_t    polled_uid = {
           .uid = {0xDE, 0xAD, 0xBE, 0xEF},
             .uid_length = 4, .tg = 1, .sak = 0x00
    };

    /* GET_VERSION answered: one raw exchange, the card stays selected. */
    static const struct
    {
        const uint8_t   *version;
        pn532_nfc_type_t subtype;
        uint16_t         pages;
    } versions[] = {
        {ntag215, PN532_MIFARE_NTAG215,        135},
        {ntag210, PN532_MIFARE_NTAG210,        20 },
        {ul_ev1,  PN532_MIFARE_ULTRALIGHT_EV1, 20 },
    };
    for (size_t i = 0; i < ARRAY_SIZE(versions); i++) {
        sim_init(&mock, &pn532, sim_type2_card, send_buf, recv_buf);
        mock.sim_version = versions[i].version;
        pn532_uid_t uid  = polled_uid;
        TEST_ASSERT_TRUE(
            pn532_14443_detect_selected_card_type_and_capacity(&pn532, &uid, &blocks, &block_size, &needs_reselect));
        TEST_ASSERT_EQUAL(versions[i].subtype, uid.subtype);
        TEST_ASSERT_EQUAL_UINT16(versions[i].pages, blocks);
        TEST_ASSERT_EQUAL_UINT16(4, block_size);
        TEST_ASSERT_FALSE(needs_reselect);
        const uint8_t expected[] = {PN532_COMMAND_INCOMMUNICATETHRU};
        assert_commands(&mock, expected, ARRAY_SIZE(expected));
        /* InCommunicateThru carries the raw command, without a target number. */
        TEST_ASSERT_EQUAL(1, mock.exchange_params_len[0]);
        TEST_ASSERT_EQUAL_HEX8(0x60, mock.exchange_params[0][0]);
    }

    /* No GET_VERSION: the card is listed again and asked for an Ultralight C challenge. */
    for (int ulc = 0; ulc < 2; ulc++) {
        sim_init(&mock, &pn532, sim_type2_card, send_buf, recv_buf);
        mock.sim_ulc    = (ulc == 1);
        pn532_uid_t uid = polled_uid;
        TEST_ASSERT_TRUE(
            pn532_14443_detect_selected_card_type_and_capacity(&pn532, &uid, &blocks, &block_size, &needs_reselect));
        TEST_ASSERT_EQUAL(ulc ? PN532_MIFARE_ULTRALIGHT_C : PN532_MIFARE_ULTRALIGHT, uid.subtype);
        TEST_ASSERT_EQUAL_UINT16(ulc ? 44 : 16, blocks);
        TEST_ASSERT_TRUE(needs_reselect);
        TEST_ASSERT_TRUE(pn532.tg_stale);
        const uint8_t expected[] = {PN532_COMMAND_INCOMMUNICATETHRU, PN532_COMMAND_RFCONFIGURATION,
                                    PN532_COMMAND_INLISTPASSIVETARGET, PN532_COMMAND_INSELECT,
                                    PN532_COMMAND_INCOMMUNICATETHRU};
        assert_commands(&mock, expected, ARRAY_SIZE(expected));
        TEST_ASSERT_EQUAL_HEX8(0x1A, mock.exchange_params[1][0]);
    }

    /* Without a selected card only the SAK is used: no target listed, or
     * listed (as after a poll) but without an open session. */
    for (int listed = 0; listed < 2; listed++) {
        sim_init(&mock, &pn532, sim_type2_card, send_buf, recv_buf);
        mock.sim_version     = ntag215;
        pn532.inListedTag    = (uint8_t)listed;
        pn532.session_opened = false;
        pn532_uid_t uid      = polled_uid;
        TEST_ASSERT_TRUE(
            pn532_14443_detect_selected_card_type_and_capacity(&pn532, &uid, &blocks, &block_size, &needs_reselect));
        TEST_ASSERT_EQUAL(PN532_MIFARE_ULTRALIGHT, uid.subtype);
        TEST_ASSERT_FALSE(needs_reselect);
        TEST_ASSERT_EQUAL(0, mock.command_count);
    }
}

TEST_CASE("capability container size does not replace a subtype the card reported", "[pn532][ndef][t2]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    memory[48 * 4]               = {0};

    /* Ultralight C: its CC announces 144 bytes, the same as an NTAG213. */
    memory[12] = 0xE1;
    memory[13] = 0x10;
    memory[14] = 0x12;
    memory[16] = 0x03;
    memory[17] = sizeof(sim_ndef_text);
    memcpy(&memory[18], sim_ndef_text, sizeof(sim_ndef_text));

    sim_init(&mock, &pn532, sim_type2_card, send_buf, recv_buf);
    mock.sim_memory = memory;
    mock.sim_units  = 48;

    pn532_uid_t uid = {
        .uid          = {0xDE, 0xAD, 0xBE, 0xEF},
        .uid_length   = 4,
        .tg           = 1,
        .sak          = 0x00,
        .subtype      = PN532_MIFARE_ULTRALIGHT_C,
        .block_size   = 4,
        .blocks_count = 44
    };
    pn532_ndef_message_parsed_t *msg = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_read_card_auto(&pn532, &uid, &msg));
    pn532_ndef_free_parsed_message(msg);
    TEST_ASSERT_EQUAL(PN532_MIFARE_ULTRALIGHT_C, uid.subtype);

    uid.subtype = PN532_MIFARE_ULTRALIGHT;
    msg         = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_read_card_auto(&pn532, &uid, &msg));
    pn532_ndef_free_parsed_message(msg);
    TEST_ASSERT_EQUAL(PN532_MIFARE_NTAG213, uid.subtype);
}

/* CRC-8 of a MIFARE Application Directory, as the NXP MAD documentation defines it. */
static uint8_t test_mad_crc(const uint8_t *data, size_t len)
{
    uint8_t crc = 0xC7;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            bool carry = (crc & 0x80) != 0;
            crc        = (uint8_t)(crc << 1);
            if (carry) {
                crc ^= 0x1D;
            }
        }
    }
    return crc;
}

TEST_CASE("MIFARE Classic NDEF is read through a MAD with a valid CRC only", "[pn532][ndef][classic][mad]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    memory[64 * 16]              = {0};

    /* The example of the NXP MAD documentation gives CRC 89h. */
    static const uint8_t doc_example[31] = {0x01, 0x01, 0x08, 0x01, 0x08, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x04, 0x00, 0x03, 0x10, 0x03, 0x10, 0x02, 0x10, 0x02,
                                            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x30};
    TEST_ASSERT_EQUAL_HEX8(0x89, test_mad_crc(doc_example, sizeof(doc_example)));

    /* MAD1 in blocks 1 and 2: CRC, info byte, then the NDEF application (03E1h) in sector 1. */
    uint8_t *mad       = &memory[16];
    mad[1]             = 0x01;
    mad[2]             = 0x03;
    mad[3]             = 0xE1;
    mad[0]             = test_mad_crc(&mad[1], 31);
    memory[3 * 16 + 9] = 0xC1; /* general purpose byte: MAD present, version 1 */
    memory[4 * 16]     = 0x03;
    memory[4 * 16 + 1] = sizeof(sim_ndef_text);
    memcpy(&memory[4 * 16 + 2], sim_ndef_text, sizeof(sim_ndef_text));
    memory[4 * 16 + 2 + sizeof(sim_ndef_text)] = 0xFE;

    pn532_uid_t uid = {
        .uid          = {0xDE, 0xAD, 0xBE, 0xEF},
        .uid_length   = 4,
        .tg           = 1,
        .sak          = 0x08,
        .subtype      = PN532_MIFARE_CLASSIC_1K,
        .block_size   = 16,
        .blocks_count = 64
    };

    sim_init(&mock, &pn532, sim_classic_card, send_buf, recv_buf);
    mock.sim_memory                  = memory;
    mock.sim_units                   = 64;
    pn532_ndef_message_parsed_t *msg = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_OK, pn532_ndef_read_card_auto(&pn532, &uid, &msg));
    TEST_ASSERT_NOT_NULL(msg);
    TEST_ASSERT_EQUAL(1, msg->record_count);
    pn532_ndef_free_parsed_message(msg);

    /* A directory whose CRC does not match its content is treated as absent:
     * only the trailer and the two MAD blocks are read. */
    mad[0] ^= 0x01;
    sim_init(&mock, &pn532, sim_classic_card, send_buf, recv_buf);
    mock.sim_memory = memory;
    mock.sim_units  = 64;
    msg             = NULL;
    TEST_ASSERT_EQUAL(PN532_NDEF_ERR_NO_NDEF, pn532_ndef_read_card_auto(&pn532, &uid, &msg));
    TEST_ASSERT_NULL(msg);
    TEST_ASSERT_EQUAL(3, mock.sim_reads);
}

TEST_CASE("Type 4 NDEF read checks mapping version, read access and NLEN", "[pn532][ndef][t4]")
{
    mock_bus_t mock;
    pn532_t    pn532;
    uint8_t    send_buf[PN532_MAX_BUF_SIZE] = {0};
    uint8_t    recv_buf[PN532_MAX_BUF_SIZE] = {0};

    /* CCLEN, mapping 2.0, MLe 59, MLc 52, NDEF File Control TLV: file E104h, 32 bytes, free access. */
    static const uint8_t good_cc[15]   = {0x00, 0x0F, 0x20, 0x00, 0x3B, 0x00, 0x34, 0x04,
                                          0x06, 0xE1, 0x04, 0x00, 0x20, 0x00, 0x00};
    uint8_t              ndef_file[32] = {0x00, sizeof(sim_ndef_text)};
    memcpy(&ndef_file[2], sim_ndef_text, sizeof(sim_ndef_text));

    pn532_uid_t uid = {
        .uid        = {0xDE, 0xAD, 0xBE, 0xEF},
        .uid_length = 4,
        .tg         = 1,
        .sak        = 0x20,
        .subtype    = PN532_MIFARE_DESFIRE,
        .block_size = 1
    };

    static const struct
    {
        size_t              cc_offset; /* CC byte to change; 0 leaves the CC as it is */
        uint8_t             cc_value;
        uint8_t             nlen;
        pn532_ndef_result_t expected;
        size_t              reads; /* READ BINARY commands: CC, NLEN, data */
    } cases[] = {
        {0,  0,    sizeof(sim_ndef_text), PN532_NDEF_OK,                3},
        {2,  0x40, sizeof(sim_ndef_text), PN532_NDEF_ERR_UNSUPPORTED,   1},
        {2,  0x00, sizeof(sim_ndef_text), PN532_NDEF_ERR_UNSUPPORTED,   1},
        {2,  0x10, sizeof(sim_ndef_text), PN532_NDEF_OK,                3},
        {13, 0x80, sizeof(sim_ndef_text), PN532_NDEF_ERR_ACCESS_DENIED, 1},
        {7,  0x06, sizeof(sim_ndef_text), PN532_NDEF_ERR_UNSUPPORTED,   1}, /* Extended NDEF File Control TLV */
        {7,  0x05, sizeof(sim_ndef_text), PN532_NDEF_ERR_PARSE_FAILED,  1},
        {0,  0,    31,                    PN532_NDEF_ERR_PARSE_FAILED,  2},
        {0,  0,    0,                     PN532_NDEF_ERR_NO_NDEF,       2},
    };

    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        uint8_t cc[15];
        memcpy(cc, good_cc, sizeof(cc));
        if (cases[i].cc_offset != 0) {
            cc[cases[i].cc_offset] = cases[i].cc_value;
        }
        ndef_file[1] = cases[i].nlen;

        sim_init(&mock, &pn532, sim_type4_card, send_buf, recv_buf);
        mock.sim_cc_file       = cc;
        mock.sim_ndef_file     = ndef_file;
        mock.sim_ndef_file_len = sizeof(ndef_file);

        pn532_ndef_message_parsed_t *msg = NULL;
        TEST_ASSERT_EQUAL_MESSAGE(cases[i].expected, pn532_ndef_read_card_auto(&pn532, &uid, &msg), "result");
        TEST_ASSERT_EQUAL_MESSAGE(cases[i].reads, mock.sim_reads, "READ BINARY count");
        if (cases[i].expected == PN532_NDEF_OK) {
            TEST_ASSERT_NOT_NULL(msg);
            pn532_ndef_free_parsed_message(msg);
        } else {
            TEST_ASSERT_NULL(msg);
        }
    }
    TEST_ASSERT_EQUAL_STRING("NDEF data is read protected", pn532_ndef_result_to_string(PN532_NDEF_ERR_ACCESS_DENIED));
}

void app_main(void)
{
    unity_run_menu();
}
