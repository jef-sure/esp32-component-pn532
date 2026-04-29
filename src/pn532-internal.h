#pragma once

#include "pn532.h"

typedef bool (*pn532_bus_write_command_t)(pn532_bus_t *bus, const uint8_t *buffer, size_t len);
typedef bool (*pn532_bus_read_data_t)(pn532_bus_t *bus, uint8_t *buffer, size_t len);
typedef bool (*pn532_bus_is_ready_t)(pn532_bus_t *bus);
typedef void (*pn532_bus_wake_t)(pn532_bus_t *bus);
typedef void (*pn532_bus_destroy_t)(pn532_bus_t *bus);

struct pn532_bus_t
{
    pn532_bus_write_command_t write_command;
    pn532_bus_read_data_t     read_data;
    pn532_bus_is_ready_t      is_ready;
    pn532_bus_wake_t          wake;
    pn532_bus_destroy_t       destroy;
};

#define PN532_PREAMBLE   (0x00)
#define PN532_STARTCODE1 (0x00)
#define PN532_STARTCODE2 (0xFF)
#define PN532_POSTAMBLE  (0x00)

#define PN532_HOSTTOPN532 (0xD4)
#define PN532_PN532TOHOST (0xD5)

#define PN532_COMMAND_GETFIRMWAREVERSION  (0x02)
#define PN532_COMMAND_SAMCONFIGURATION    (0x14)
#define PN532_COMMAND_RFCONFIGURATION     (0x32)
#define PN532_COMMAND_INLISTPASSIVETARGET (0x4A)
#define PN532_COMMAND_INDATAEXCHANGE      (0x40)
#define PN532_COMMAND_INRELEASE           (0x52)
#define PN532_COMMAND_INSELECT            (0x54)

#define PN532_SPI_STATREAD  (0x02)
#define PN532_SPI_DATAWRITE (0x01)
#define PN532_SPI_DATAREAD  (0x03)
#define PN532_SPI_READY     (0x01)

#define PN532_MIFARE_ISO14443A (0x00)

bool pn532_execute_command(pn532_t *pn532, uint8_t command, const uint8_t *params, size_t params_len, uint8_t *response,
                           size_t *response_len, uint16_t timeout);
bool pn532_release_target(pn532_t *pn532);
bool pn532_in_data_exchange(pn532_t *pn532, const uint8_t *data, size_t data_len, uint8_t *response,
                            size_t *response_len, uint16_t timeout);
bool pn532_in_select(pn532_t *pn532, uint8_t target_number);