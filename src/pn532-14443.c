#include "pn532-internal.h"
#include "pn532-mifare.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"

static const char *TAG_T4 = "PN532-T4";

#define PN532_MAX_PASSIVE_TARGETS_ISO14443A 2
#define PN532_TYPE4_EXCHANGE_TIMEOUT_MS     1500

static bool pn532_prepare_for_passive_target_list(pn532_t *pn532, bool auto_rats)
{
    if (pn532 == NULL) {
        return false;
    }

    /* NXP's libnfc/TAMA stack halts RF before every InListPassiveTarget
     * because the PN532 can stay in a state where the next poll is unreliable
     * until the field is recycled. The next list command restarts the field.
     * pn532_set_rf_off() already applies the configurable RF settle delay
     * (pn532->rf_settle_delay_ms) so a HALT-state card powers down cleanly. */
    pn532->rf_config = PN532_MIFARE_ISO14443A;
    if (!pn532_set_rf_off(pn532)) {
        return false;
    }
    pn532->session_opened = false;

    /* NXP pollPassive106A(): SetParameters precedes the list command.
     * Automatic RATS is on for discovery and ISO14443-4 targets and off when
     * a MIFARE Classic emulation card must stay at the ISO14443-3 level. */
    return pn532_set_auto_rats(pn532, auto_rats);
}

/* MIFARE Classic emulation on an ISO14443-4 card (SAK 0x28/0x38): with
 * automatic RATS the PN532 activates it as ISO-DEP and it no longer accepts
 * MIFARE commands. The NXP reference lists such cards with RATS switched off
 * in its MIFARE mode. */
static bool pn532_uid_is_classic_emulation(const pn532_uid_t *uid)
{
    switch (uid->subtype) {
    case PN532_MIFARE_CLASSIC_1K:
    case PN532_MIFARE_CLASSIC_MINI:
    case PN532_MIFARE_CLASSIC_4K:
        return (uid->sak & 0x20u) != 0u;
    default:
        return false;
    }
}

bool pn532_14443_detect_card_type_and_capacity(pn532_uid_t *uid, uint16_t *blocks_count, uint16_t *block_size)
{
    if (uid == NULL || blocks_count == NULL || block_size == NULL) {
        return false;
    }

    uid->subtype  = PN532_MIFARE_UNKNOWN;
    *blocks_count = 0;
    *block_size   = 0;

    switch (uid->sak & 0x7F) {
    case 0x00:
        uid->subtype  = PN532_MIFARE_ULTRALIGHT;
        *blocks_count = 16;
        *block_size   = 4;
        break;
    case 0x08:
        uid->subtype  = PN532_MIFARE_CLASSIC_1K;
        *blocks_count = 64;
        *block_size   = 16;
        break;
    case 0x09:
        uid->subtype  = PN532_MIFARE_CLASSIC_MINI;
        *blocks_count = 20;
        *block_size   = 16;
        break;
    case 0x10:
    case 0x11:
        uid->subtype  = PN532_MIFARE_PLUS_2K;
        *blocks_count = 128;
        *block_size   = 16;
        break;
    case 0x18:
    case 0x38:
        uid->subtype  = PN532_MIFARE_CLASSIC_4K;
        *blocks_count = 256;
        *block_size   = 16;
        break;
    case 0x20:
    case 0x24:
        uid->subtype  = PN532_MIFARE_DESFIRE;
        *blocks_count = 0;
        *block_size   = 1;
        break;
    case 0x28:
        uid->subtype  = PN532_MIFARE_CLASSIC_1K;
        *blocks_count = 64;
        *block_size   = 16;
        break;
    default:
        break;
    }

    uid->blocks_count = *blocks_count;
    uid->block_size   = *block_size;
    return true;
}

bool pn532_14443_detect_selected_card_type_and_capacity( //
    pn532_t     *pn532,                                  //
    pn532_uid_t *uid,                                    //
    uint16_t    *blocks_count,                           //
    uint16_t    *block_size,                             //
    bool        *needs_reselect                          //
)
{
    (void)pn532;

    if (uid == NULL || blocks_count == NULL || block_size == NULL || needs_reselect == NULL) {
        return false;
    }

    *needs_reselect = false;
    return pn532_14443_detect_card_type_and_capacity(uid, blocks_count, block_size);
}

bool pn532_14443_block_read(pn532_t *pn532, int blockno, uint8_t *buffer, size_t buffer_len)
{
    return pn532_mifare_block_read(pn532, blockno, buffer, buffer_len);
}

int pn532_14443_block_write(pn532_t *pn532, int blockno, const uint8_t *buffer, size_t buffer_len)
{
    return pn532_mifare_block_write(pn532, blockno, buffer, buffer_len);
}

/* ISO/IEC 14443-3 SAK bit 6 (0x20): the card is ISO/IEC 14443-4 compliant. The
 * PN532 then sends RATS on its own and appends the ATS to the target entry,
 * whatever the other SAK bits say (0x28/0x38 Classic emulation, 0x60 with
 * NFC-DEP). */
static bool pn532_target_has_ats(uint8_t sak)
{
    return (sak & 0x20u) != 0u;
}

static bool pn532_parse_iso14443a_target( //
    const uint8_t *response,              //
    size_t         response_len,          //
    bool           expect_ats,            //
    size_t        *offset,                //
    pn532_uid_t   *uid                    //
)
{
    size_t entry_len;

    if (response == NULL || offset == NULL || uid == NULL) {
        return false;
    }
    if (*offset + 5 > response_len) {
        return false;
    }

    memset(uid, 0, sizeof(*uid));
    uid->tg         = response[*offset];
    uid->atqa       = ((uint16_t)response[*offset + 1] << 8) | (uint16_t)response[*offset + 2];
    uid->sak        = response[*offset + 3];
    uid->uid_length = (int8_t)response[*offset + 4];
    if (uid->uid_length < 0 || (size_t)uid->uid_length > sizeof(uid->uid)) {
        return false;
    }

    entry_len = 5u + (size_t)uid->uid_length;
    if (*offset + entry_len > response_len) {
        return false;
    }

    memcpy(uid->uid, response + *offset + 5u, (size_t)uid->uid_length);

    /* No ATS follows while automatic RATS is switched off. */
    if (expect_ats && pn532_target_has_ats(uid->sak) && *offset + entry_len < response_len) {
        uint8_t ats_len;

        ats_len = response[*offset + entry_len];
        if (ats_len == 0 || *offset + entry_len + ats_len > response_len) {
            return false;
        }
        entry_len += ats_len;
    }

    *offset += entry_len;
    return true;
}

static bool pn532_find_listed_target_by_uid( //
    const uint8_t     *response,             //
    size_t             response_len,         //
    bool               expect_ats,           //
    const pn532_uid_t *wanted_uid,           //
    uint8_t           *target_number         //
)
{
    if (response == NULL || wanted_uid == NULL || target_number == NULL || response_len == 0 || response[0] == 0) {
        return false;
    }

    size_t  offset        = 1;
    uint8_t targets_found = response[0];
    if (targets_found > PN532_MAX_PASSIVE_TARGETS_ISO14443A) {
        targets_found = PN532_MAX_PASSIVE_TARGETS_ISO14443A;
    }

    for (uint8_t index = 0; index < targets_found; index++) {
        pn532_uid_t parsed_uid;

        if (!pn532_parse_iso14443a_target(response, response_len, expect_ats, &offset, &parsed_uid)) {
            return false;
        }

        if ((uint8_t)parsed_uid.uid_length == (uint8_t)wanted_uid->uid_length &&
            memcmp(parsed_uid.uid, wanted_uid->uid, (size_t)parsed_uid.uid_length) == 0) {
            *target_number = parsed_uid.tg;
            return true;
        }
    }

    return false;
}

/* The PN532 numbers targets from 1 again on every InListPassiveTarget, so a
 * Tg kept in an older pn532_uid_t may by now belong to another card. Keep the
 * UID behind each Tg of the latest listing to tell the two apart. */
static void pn532_remember_listed_targets(pn532_t *pn532, const uint8_t *response, size_t response_len)
{
    if (response_len == 0) {
        return;
    }

    size_t  offset        = 1;
    uint8_t targets_found = response[0];
    if (targets_found > PN532_MAX_PASSIVE_TARGETS_ISO14443A) {
        targets_found = PN532_MAX_PASSIVE_TARGETS_ISO14443A;
    }

    for (uint8_t index = 0; index < targets_found; index++) {
        pn532_uid_t parsed_uid;

        if (!pn532_parse_iso14443a_target(response, response_len, !pn532->auto_rats_off, &offset, &parsed_uid)) {
            return;
        }
        if (parsed_uid.tg >= 1 && parsed_uid.tg <= PN532_MAX_PASSIVE_TARGETS_ISO14443A) {
            memcpy(pn532->listed_uid[parsed_uid.tg - 1], parsed_uid.uid, (size_t)parsed_uid.uid_length);
            pn532->listed_uid_len[parsed_uid.tg - 1] = (uint8_t)parsed_uid.uid_length;
        }
    }
}

static bool pn532_tg_holds_uid(const pn532_t *pn532, const pn532_uid_t *uid)
{
    if (uid->tg < 1 || uid->tg > PN532_MAX_PASSIVE_TARGETS_ISO14443A) {
        return false;
    }
    return pn532->listed_uid_len[uid->tg - 1] == (uint8_t)uid->uid_length &&
           memcmp(pn532->listed_uid[uid->tg - 1], uid->uid, (size_t)uid->uid_length) == 0;
}

static bool pn532_list_passive_iso14443a_targets( //
    pn532_t       *pn532,                         //
    uint8_t        max_targets,                   //
    const uint8_t *initiator_data,                //
    size_t         initiator_data_len,            //
    uint8_t       *response,                      //
    size_t        *response_len,                  //
    uint16_t       timeout                        //
)
{
    /* UM0701-02 §7.3.5: the InListPassiveTarget InitiatorData for a cascaded
     * UID must contain the cascade tag 0x88 in front of every cascade level
     * except the last one. Callers hand us the plain UID stored in pn532_uid_t,
     * so the tags are inserted here into a local copy: 4-byte UID stays 4
     * bytes, 7-byte becomes 8, 10-byte becomes 12. */
    uint8_t params[2 + 12];
    uint8_t cascaded[12];
    size_t  cascaded_len = 0;
    size_t  params_len   = 2;

    if (pn532 == NULL || response == NULL || response_len == NULL) {
        return false;
    }
    if (initiator_data_len != 0 && initiator_data_len != 4 && initiator_data_len != 7 && initiator_data_len != 10) {
        return false;
    }
    if (initiator_data == NULL && initiator_data_len != 0) {
        return false;
    }

    if (initiator_data != NULL && initiator_data_len > 0) {
        size_t pos = 0;
        while (pos < initiator_data_len) {
            size_t remaining = initiator_data_len - pos;
            if (remaining > 4) {
                cascaded[cascaded_len++] = 0x88;
                memcpy(cascaded + cascaded_len, initiator_data + pos, 3);
                cascaded_len += 3;
                pos += 3;
            } else {
                memcpy(cascaded + cascaded_len, initiator_data + pos, remaining);
                cascaded_len += remaining;
                pos += remaining;
            }
        }
    }

    params[0] = max_targets;
    params[1] = PN532_MIFARE_ISO14443A;
    if (cascaded_len > 0) {
        memcpy(params + 2, cascaded, cascaded_len);
        params_len += cascaded_len;
    }

    memset(pn532->listed_uid_len, 0, sizeof(pn532->listed_uid_len));
    if (!pn532_execute_command(pn532, PN532_COMMAND_INLISTPASSIVETARGET, params, params_len, response, response_len,
                               timeout)) {
        return false;
    }
    pn532_remember_listed_targets(pn532, response, *response_len);
    return true;
}

static pn532_poll_status_t pn532_poll_command_error(const pn532_t *pn532)
{
    if (pn532 != NULL) {
        if (pn532->last_command_status == PN532_COMMAND_STATUS_TIMEOUT) {
            return PN532_POLL_TIMEOUT;
        }
        if (pn532->last_command_status == PN532_COMMAND_STATUS_OK) {
            /* The transport delivered a well-formed frame but the chip
             * refused the command (non-zero poll/release status): a protocol
             * problem, not a dead link. Recovery would be wasted effort. */
            return PN532_POLL_PROTOCOL_ERROR;
        }
    }
    /* ACK timeouts and hard transport failures both mean the PN532 is not
     * talking to us; report them as transport errors, not RF problems. */
    return PN532_POLL_TRANSPORT_ERROR;
}

pn532_uids_array_t *pn532_14443_get_all_uids_ex(pn532_t *pn532, pn532_poll_status_t *status)
{
    /* Two targets with long ATS can exceed any small buffer; a too-small one
     * would surface as a misleading PN532_POLL_TRANSPORT_ERROR. */
    uint8_t     response[PN532_MAX_BUF_SIZE];
    size_t      response_len = sizeof(response);
    uint8_t     targets_found;
    size_t      alloc_size;
    size_t      offset;
    pn532_uid_t parsed_uid;

    if (status != NULL) {
        *status = PN532_POLL_INVALID_ARGUMENT;
    }
    if (pn532 == NULL) {
        return NULL;
    }

    if (!pn532_release_target(pn532)) {
        if (status != NULL) {
            *status = pn532_poll_command_error(pn532);
        }
        return NULL;
    }

    if (!pn532_prepare_for_passive_target_list(pn532, true)) {
        if (status != NULL) {
            *status = pn532_poll_command_error(pn532);
        }
        return NULL;
    }

    if (!pn532_list_passive_iso14443a_targets(pn532, PN532_MAX_PASSIVE_TARGETS_ISO14443A, NULL, 0, response,
                                              &response_len, (uint16_t)pn532->timeout_ms)) {
        if (status != NULL) {
            *status = pn532_poll_command_error(pn532);
        }
        return NULL;
    }
    pn532->is_rf_on = true;
    pn532->tg_stale = false;
    if (response_len == 0) {
        if (status != NULL) {
            *status = PN532_POLL_PROTOCOL_ERROR;
        }
        return NULL;
    }
    if (response[0] == 0) {
        if (status != NULL) {
            *status = PN532_POLL_NO_TARGET;
        }
        return NULL;
    }

    targets_found = response[0];
    if (targets_found > PN532_MAX_PASSIVE_TARGETS_ISO14443A) {
        targets_found = PN532_MAX_PASSIVE_TARGETS_ISO14443A;
    }

    alloc_size = sizeof(pn532_uids_array_t) + ((size_t)targets_found - 1u) * sizeof(pn532_uid_t);

    pn532_uids_array_t *uids = calloc(1, alloc_size);
    if (uids == NULL) {
        if (status != NULL) {
            *status = PN532_POLL_NO_MEMORY;
        }
        return NULL;
    }

    offset           = 1;
    uids->uids_count = 0;
    for (uint8_t index = 0; index < targets_found; index++) {
        uint16_t blocks_count = 0;
        uint16_t block_size   = 0;

        if (!pn532_parse_iso14443a_target(response, response_len, true, &offset, &parsed_uid)) {
            free(uids);
            if (status != NULL) {
                *status = PN532_POLL_PROTOCOL_ERROR;
            }
            return NULL;
        }

        uids->uids[uids->uids_count] = parsed_uid;
        pn532_14443_detect_card_type_and_capacity(&uids->uids[uids->uids_count], &blocks_count, &block_size);
        uids->uids_count++;
    }

    if (uids->uids_count == 0) {
        free(uids);
        if (status != NULL) {
            *status = PN532_POLL_PROTOCOL_ERROR;
        }
        return NULL;
    }

    if (status != NULL) {
        *status = PN532_POLL_FOUND;
    }
    return uids;
}

pn532_uids_array_t *pn532_14443_get_all_uids(pn532_t *pn532)
{
    return pn532_14443_get_all_uids_ex(pn532, NULL);
}

bool pn532_14443_select_by_uid(pn532_t *pn532, const pn532_uid_t *uid)
{
    uint8_t response[PN532_MAX_BUF_SIZE];
    uint8_t target_number = 0;

    if (pn532 == NULL || uid == NULL) {
        return false;
    }
    if (uid->uid_length != 4 && uid->uid_length != 7 && uid->uid_length != 10) {
        return false;
    }

    /* A stale Tg (card dropped to IDLE after a failed exchange) takes the
     * full path: only a new InListPassiveTarget reliably re-activates it. So
     * does a card that was listed in the other RATS mode than it needs, and a
     * Tg that a later poll gave to another card. */
    bool plain_mifare = pn532_uid_is_classic_emulation(uid);
    if (pn532_tg_holds_uid(pn532, uid) && pn532->is_rf_on && !pn532->tg_stale &&
        pn532->auto_rats_off == plain_mifare) {
        return pn532_in_select(pn532, uid->tg);
    }

    /*
     * libnfc-style targeted activation: pass the UID as InitiatorData to
     * InListPassiveTarget. The PN532 then runs REQA/anticol/SEL aimed at
     * exactly this UID instead of returning whatever cards happen to be in
     * the field. With MaxTg=1 we either get this card back or zero targets.
     */
    size_t response_len;
    bool   listed = false;
    for (int attempt = 0; attempt < 2; attempt++) {
        if (!pn532_prepare_for_passive_target_list(pn532, !plain_mifare)) {
            pn532->inListedTag    = 0;
            pn532->session_opened = false;
            return false;
        }

        response_len = sizeof(response);
        if (pn532_list_passive_iso14443a_targets(pn532, 1, uid->uid, (size_t)uid->uid_length, response, &response_len,
                                                 (uint16_t)pn532->timeout_ms)) {
            pn532->is_rf_on = true;
            pn532->tg_stale = false;
            listed          = true;
            break;
        }
    }
    if (!listed || !pn532_find_listed_target_by_uid(response, response_len, !plain_mifare, uid, &target_number)) {
        if (!pn532_prepare_for_passive_target_list(pn532, !plain_mifare)) {
            pn532->inListedTag    = 0;
            pn532->session_opened = false;
            return false;
        }

        response_len = sizeof(response);
        if (!pn532_list_passive_iso14443a_targets(pn532, PN532_MAX_PASSIVE_TARGETS_ISO14443A, NULL, 0, response,
                                                  &response_len, (uint16_t)pn532->timeout_ms)) {
            pn532->inListedTag    = 0;
            pn532->session_opened = false;
            return false;
        }
        pn532->is_rf_on = true;
        pn532->tg_stale = false;

        if (!pn532_find_listed_target_by_uid(response, response_len, !plain_mifare, uid, &target_number)) {
            (void)pn532_set_rf_off(pn532);
            pn532->inListedTag    = 0;
            pn532->session_opened = false;
            return false;
        }
    }

    if (!pn532_in_select(pn532, target_number)) {
        (void)pn532_set_rf_off(pn532);
        pn532->inListedTag    = 0;
        pn532->session_opened = false;
        return false;
    }

    return true;
}

bool pn532_14443_authenticate(pn532_t *pn532, const uint8_t *key, uint8_t key_type, const pn532_uid_t *uid, int blockno)
{
    if (pn532 == NULL || key == NULL || uid == NULL) {
        return false;
    }

    if (uid->subtype == PN532_MIFARE_ULTRALIGHT || uid->subtype == PN532_MIFARE_ULTRALIGHT_C ||
        uid->subtype == PN532_MIFARE_ULTRALIGHT_EV1 || uid->subtype == PN532_MIFARE_NTAG213 ||
        uid->subtype == PN532_MIFARE_NTAG215 || uid->subtype == PN532_MIFARE_NTAG216 ||
        uid->subtype == PN532_MIFARE_DESFIRE) {
        return true;
    }

    const uint8_t *uid_for_auth = uid->uid;
    if (uid->uid_length == 7) {
        uid_for_auth = &uid->uid[3];
    } else if (uid->uid_length == 10) {
        uid_for_auth = &uid->uid[6];
    }

    return pn532_mifare_authenticate(pn532, (uint8_t)blockno, key, key_type, uid_for_auth) == 0;
}

bool pn532_14443_4_transceive(pn532_t *pn532, const uint8_t *apdu, size_t apdu_len, uint8_t *rx, size_t *rx_len)
{
    if (pn532 == NULL || apdu == NULL || apdu_len == 0 || rx == NULL || rx_len == NULL || *rx_len == 0) {
        return false;
    }
    if (pn532->inListedTag == 0) {
        return false;
    }

    /*
     * PN532 InDataExchange (UM0701-02 §7.3.8): for a Type-A T=CL target the
     * firmware adds the PCB, manages the I-block toggle, handles WTX and
     * chaining, and strips the framing on the way back. We just feed APDU in
     * and get APDU + SW back. Give Type 4 exchanges more headroom than the
     * generic 500 ms command timeout because any WTX handling is opaque to
     * the host while the firmware waits for the card's final response.
     */
    if (!pn532->session_opened && !pn532_in_select(pn532, pn532->inListedTag)) {
        return false;
    }
    uint16_t timeout = pn532->timeout_ms;
    if (timeout < PN532_TYPE4_EXCHANGE_TIMEOUT_MS) {
        timeout = PN532_TYPE4_EXCHANGE_TIMEOUT_MS;
    }
    return pn532_in_data_exchange(pn532, apdu, apdu_len, rx, rx_len, timeout);
}

/* One SELECT exchange; *card_refused reports a well-formed error status word. */
static bool pn532_14443_4_select(pn532_t *pn532, uint8_t p1, uint8_t p2, const uint8_t *file_id, size_t file_id_len,
                                 bool *card_refused)
{
    uint8_t apdu[5 + 16];
    apdu[0] = 0x00;                 /* CLA */
    apdu[1] = 0xA4;                 /* INS = SELECT */
    apdu[2] = p1;                   /* P1 */
    apdu[3] = p2;                   /* P2 */
    apdu[4] = (uint8_t)file_id_len; /* Lc */
    memcpy(&apdu[5], file_id, file_id_len);

    *card_refused = false;

    uint8_t rx[64];
    size_t  rx_len = sizeof(rx);
    if (!pn532_14443_4_transceive(pn532, apdu, 5u + file_id_len, rx, &rx_len)) {
        return false;
    }

    pn532_apdu_response_t response;
    if (pn532_apdu_parse_response(rx, rx_len, &response) != ESP_OK) {
        return false;
    }
    if (pn532_apdu_get_status(&response) == PN532_APDU_SW_SUCCESS) {
        return true;
    }
    ESP_LOGD(TAG_T4, "SELECT P1=%02X P2=%02X failed SW=%02X%02X", p1, p2, response.sw1, response.sw2);
    *card_refused = true;
    return false;
}

bool pn532_14443_4_select_file(pn532_t *pn532, const uint8_t *file_id, size_t file_id_len)
{
    if (pn532 == NULL || file_id == NULL || file_id_len == 0 || file_id_len > 16) {
        return false;
    }

    bool card_refused = false;
    if (file_id_len > 2) {
        /* By AID: first or only occurrence, FCI optional. */
        return pn532_14443_4_select(pn532, 0x04, 0x00, file_id, file_id_len, &card_refused);
    }

    /* By file identifier. NFC Forum Type 4 Tag mapping 2.0 mandates P2=0x0C
     * (no response data); mapping 1.0 cards expect P2=0x00, so that is tried
     * once when the card itself refuses the first form. */
    if (pn532_14443_4_select(pn532, 0x00, 0x0C, file_id, file_id_len, &card_refused)) {
        return true;
    }
    return card_refused && pn532_14443_4_select(pn532, 0x00, 0x00, file_id, file_id_len, &card_refused);
}

bool pn532_14443_4_read_binary(pn532_t *pn532, uint16_t offset, uint8_t le, uint8_t *buffer, size_t *got)
{
    if (pn532 == NULL || buffer == NULL || got == NULL) {
        return false;
    }
    /* Short EF identifier mode encodes only bits 1..15 of the offset in
     * P1/P2 (b8 of P1 must stay 0, ISO 7816-4 §5.1.1). Reject instead of
     * silently wrapping offsets at/above 0x8000. */
    if (offset > 0x7FFFu) {
        ESP_LOGE(TAG_T4, "READ BINARY offset 0x%04X exceeds the 0x7FFF short-file limit", offset);
        return false;
    }

    uint8_t apdu[5];
    apdu[0] = 0x00;                            /* CLA */
    apdu[1] = 0xB0;                            /* INS = READ BINARY */
    apdu[2] = (uint8_t)((offset >> 8) & 0x7F); /* P1: high byte (b8 = 0 for short EF identifier mode) */
    apdu[3] = (uint8_t)(offset & 0xFF);        /* P2: low byte */
    apdu[4] = le;                              /* Le */

    uint8_t rx[260];
    size_t  rx_len = sizeof(rx);
    if (!pn532_14443_4_transceive(pn532, apdu, sizeof(apdu), rx, &rx_len)) {
        return false;
    }

    pn532_apdu_response_t response;
    if (pn532_apdu_parse_response(rx, rx_len, &response) != ESP_OK) {
        return false;
    }
    if (pn532_apdu_get_status(&response) != PN532_APDU_SW_SUCCESS) {
        ESP_LOGD(TAG_T4, "READ BINARY @0x%04X len=%u SW=%02X%02X", offset, le, response.sw1, response.sw2);
        return false;
    }

    if (response.data_len > *got) {
        /* The R-APDU does not fit the caller's buffer. Report the required
         * size so the caller can retry, instead of silently truncating a
         * payload the contract promised to deliver whole. */
        ESP_LOGE(TAG_T4, "READ BINARY @0x%04X: %u bytes arrived, buffer holds %u", offset, (unsigned)response.data_len,
                 (unsigned)*got);
        *got = response.data_len;
        return false;
    }
    memcpy(buffer, response.data, response.data_len);
    *got = response.data_len;
    return true;
}
