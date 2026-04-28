#include "pn532-internal.h"
#include "pn532-mifare.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_rom_sys.h"

static const char *TAG_T4 = "PN532-T4";

#define PN532_MAX_PASSIVE_TARGETS_ISO14443A 2
#define PN532_TYPE4_EXCHANGE_TIMEOUT_MS     1500

static bool pn532_prepare_for_passive_target_list(pn532_t *pn532)
{
    if (pn532 == NULL) {
        return false;
    }

    /* NXP's libnfc/TAMA stack halts RF before every InListPassiveTarget
     * because the PN532 can stay in a state where the next poll is unreliable
     * until the field is recycled. The next list command restarts the field. */
    pn532->rf_config = PN532_MIFARE_ISO14443A;
    if (!pn532_set_rf_off(pn532)) {
        return false;
    }
    pn532->session_opened = false;
    pn532_delay_ms(5);
    esp_rom_delay_us(100);
    return true;
}

bool pn532_14443_detect_card_type_and_capacity(pn532_uid_t *uid, uint16_t *blocks_count, uint16_t *block_size)
{
    if (uid == NULL || blocks_count == NULL || block_size == NULL) {
        return false;
    }

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
        uid->subtype  = PN532_MIFARE_CLASSIC_1K;
        *blocks_count = 64;
        *block_size   = 16;
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

static bool pn532_target_has_ats(uint8_t sak)
{
    return ((sak & 0x40u) == 0u) && ((sak & 0x20u) != 0u) && ((sak & 0x28u) != 0x28u) && ((sak & 0x30u) != 0x30u);
}

static bool pn532_parse_iso14443a_target( //
    const uint8_t *response,              //
    size_t         response_len,          //
    size_t        *offset,                //
    uint8_t       *target_number,         //
    pn532_uid_t   *uid                    //
)
{
    size_t entry_len;

    if (response == NULL || offset == NULL || target_number == NULL || uid == NULL) {
        return false;
    }
    if (*offset + 5 > response_len) {
        return false;
    }

    memset(uid, 0, sizeof(*uid));
    *target_number  = response[*offset];
    uid->atqa       = (uint16_t)response[*offset + 1] | ((uint16_t)response[*offset + 2] << 8);
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

    if (pn532_target_has_ats(uid->sak)) {
        uint8_t ats_len;

        if (*offset + entry_len >= response_len) {
            return false;
        }

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
        uint8_t     parsed_target_number = 0;

        if (!pn532_parse_iso14443a_target(response, response_len, &offset, &parsed_target_number, &parsed_uid)) {
            return false;
        }

        if ((uint8_t)parsed_uid.uid_length == (uint8_t)wanted_uid->uid_length &&
            memcmp(parsed_uid.uid, wanted_uid->uid, (size_t)parsed_uid.uid_length) == 0) {
            *target_number = parsed_target_number;
            return true;
        }
    }

    return false;
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
    uint8_t params[2 + 10];
    size_t  params_len = 2;

    if (pn532 == NULL || response == NULL || response_len == NULL) {
        return false;
    }
    if (initiator_data_len > sizeof(params) - 2) {
        return false;
    }

    params[0] = max_targets;
    params[1] = PN532_MIFARE_ISO14443A;
    if (initiator_data != NULL && initiator_data_len > 0) {
        memcpy(params + 2, initiator_data, initiator_data_len);
        params_len += initiator_data_len;
    }

    return pn532_execute_command(pn532, PN532_COMMAND_INLISTPASSIVETARGET, params, params_len, response, response_len,
                                 timeout);
}

pn532_uids_array_t *pn532_14443_get_all_uids(pn532_t *pn532)
{
    uint8_t     response[64];
    size_t      response_len = sizeof(response);
    uint8_t     targets_found;
    size_t      alloc_size;
    size_t      offset;
    uint8_t     first_target_number = 0;
    pn532_uid_t parsed_uid;

    if (pn532 == NULL) {
        return NULL;
    }

    /* Release any leftover activation before scanning. */
    (void)pn532_release_target(pn532);

    if (!pn532_prepare_for_passive_target_list(pn532)) {
        return NULL;
    }

    if (!pn532_list_passive_iso14443a_targets(pn532, PN532_MAX_PASSIVE_TARGETS_ISO14443A, NULL, 0, response,
                                              &response_len, (uint16_t)pn532->timeout_ms)) {
        return NULL;
    }
    pn532->is_rf_on = true;
    if (response_len == 0 || response[0] == 0) {
        (void)pn532_set_rf_off(pn532);
        return NULL;
    }

    targets_found = response[0];
    if (targets_found > PN532_MAX_PASSIVE_TARGETS_ISO14443A) {
        targets_found = PN532_MAX_PASSIVE_TARGETS_ISO14443A;
    }

    alloc_size = sizeof(pn532_uids_array_t) + ((size_t)targets_found - 1u) * sizeof(pn532_uid_t);

    pn532_uids_array_t *uids = calloc(1, alloc_size);
    if (uids == NULL) {
        return NULL;
    }

    offset           = 1;
    uids->uids_count = 0;
    for (uint8_t index = 0; index < targets_found; index++) {
        uint16_t blocks_count  = 0;
        uint16_t block_size    = 0;
        uint8_t  target_number = 0;

        if (!pn532_parse_iso14443a_target(response, response_len, &offset, &target_number, &parsed_uid)) {
            free(uids);
            return NULL;
        }

        uids->uids[uids->uids_count] = parsed_uid;
        pn532_14443_detect_card_type_and_capacity(&uids->uids[uids->uids_count], &blocks_count, &block_size);
        if (uids->uids_count == 0) {
            first_target_number = target_number;
            if (!pn532_in_select(pn532, target_number)) {
                free(uids);
                (void)pn532_set_rf_off(pn532);
                pn532->inListedTag    = 0;
                pn532->session_opened = false;
                return NULL;
            }
        }
        uids->uids_count++;
    }

    if (uids->uids_count == 0) {
        free(uids);
        return NULL;
    }

    if (first_target_number == 0) {
        pn532->inListedTag    = 0;
        pn532->session_opened = false;
    }

    return uids;
}

bool pn532_14443_select_by_uid(pn532_t *pn532, const pn532_uid_t *uid)
{
    uint8_t response[64];
    uint8_t target_number = 0;

    if (pn532 == NULL || uid == NULL) {
        return false;
    }
    if (uid->uid_length != 4 && uid->uid_length != 7 && uid->uid_length != 10) {
        return false;
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
        if (!pn532_prepare_for_passive_target_list(pn532)) {
            pn532->inListedTag    = 0;
            pn532->session_opened = false;
            return false;
        }

        response_len = sizeof(response);
        if (pn532_list_passive_iso14443a_targets(pn532, 1, uid->uid, (size_t)uid->uid_length, response, &response_len,
                                                 (uint16_t)pn532->timeout_ms)) {
            pn532->is_rf_on = true;
            listed          = true;
            break;
        }
    }
    if (!listed || !pn532_find_listed_target_by_uid(response, response_len, uid, &target_number)) {
        if (!pn532_prepare_for_passive_target_list(pn532)) {
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

        if (!pn532_find_listed_target_by_uid(response, response_len, uid, &target_number)) {
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

/* ---- ISO 14443-4 / T=CL APDU layer ---- */

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

bool pn532_14443_4_select_file(pn532_t *pn532, const uint8_t *file_id, size_t file_id_len)
{
    if (pn532 == NULL || file_id == NULL || file_id_len == 0 || file_id_len > 16) {
        return false;
    }

    uint8_t apdu[5 + 16];
    apdu[0] = 0x00;                     /* CLA */
    apdu[1] = 0xA4;                     /* INS = SELECT */
    apdu[2] = (file_id_len > 2) ? 0x04  /* by AID */
                                : 0x00; /* by File ID */
    apdu[3] = 0x00;                     /* P2: First or only, FCI returned */
    apdu[4] = (uint8_t)file_id_len;     /* Lc */
    memcpy(&apdu[5], file_id, file_id_len);

    uint8_t rx[64];
    size_t  rx_len = sizeof(rx);
    if (!pn532_14443_4_transceive(pn532, apdu, 5u + file_id_len, rx, &rx_len)) {
        return false;
    }
    if (rx_len < 2) {
        return false;
    }
    uint8_t sw1 = rx[rx_len - 2];
    uint8_t sw2 = rx[rx_len - 1];
    if (sw1 == 0x90 && sw2 == 0x00) {
        return true;
    }
    ESP_LOGD(TAG_T4, "SELECT failed SW=%02X%02X", sw1, sw2);
    return false;
}

bool pn532_14443_4_read_binary(pn532_t *pn532, uint16_t offset, uint8_t le, uint8_t *buffer, size_t *got)
{
    if (pn532 == NULL || buffer == NULL || got == NULL || le == 0) {
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
    if (rx_len < 2) {
        return false;
    }
    uint8_t sw1 = rx[rx_len - 2];
    uint8_t sw2 = rx[rx_len - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        ESP_LOGD(TAG_T4, "READ BINARY @0x%04X len=%u SW=%02X%02X", offset, le, sw1, sw2);
        return false;
    }

    size_t data_len = rx_len - 2;
    if (data_len > *got) {
        data_len = *got;
    }
    memcpy(buffer, rx, data_len);
    *got = data_len;
    return true;
}
