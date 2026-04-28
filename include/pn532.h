/**
 * @file pn532.h
 * @brief Public transport, device, polling, ISO14443A, and ISO-DEP API for the PN532 driver.
 * @copyright Copyright (c) 2026 Anton Petrusevich.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/spi_master.h"
#include "driver/uart.h"

/** @brief Default 7-bit PN532 I2C address in ESP-IDF's left-shifted form. */
#define PN532_I2C_DEFAULT_ADDRESS    (0x24)

/** @brief Default PN532 HSU baud rate used when uart_init() receives a non-positive baud. */
#define PN532_UART_DEFAULT_BAUD_RATE (115200)

/** @brief Maximum PN532 host frame size handled by this driver, including protocol overhead. */
#define PN532_MAX_BUF_SIZE 280

/** @brief Opaque transport handle created by one of the pn532_*_init() bus constructors. */
typedef struct pn532_bus_t pn532_bus_t;

/** @brief Card subtype inferred from ATQA/SAK and, where applicable, card layout probing. */
typedef enum _pn532_nfc_subtype_t
{
    PN532_MIFARE_UNKNOWN = 0,
    PN532_MIFARE_CLASSIC_1K,
    PN532_MIFARE_CLASSIC_MINI,
    PN532_MIFARE_CLASSIC_4K,
    PN532_MIFARE_ULTRALIGHT,
    PN532_MIFARE_ULTRALIGHT_C,
    PN532_MIFARE_ULTRALIGHT_EV1,
    PN532_MIFARE_NTAG213,
    PN532_MIFARE_NTAG215,
    PN532_MIFARE_NTAG216,
    PN532_MIFARE_PLUS_2K,
    PN532_MIFARE_PLUS_4K,
    PN532_MIFARE_DESFIRE
} __attribute__((__packed__)) pn532_nfc_type_t;

/**
 * @brief ISO14443A target description returned by polling helpers.
 *
 * The UID, ATQA, and SAK come directly from PN532 polling/select responses.
 * subtype, block_size, and blocks_count are filled by the card-type detection
 * helpers.
 */
typedef struct
{
    uint8_t          uid[10];
    int8_t           uid_length;
    uint8_t          sak;
    pn532_nfc_type_t subtype;
    uint8_t          _pad;
    uint16_t         atqa;
    uint16_t         block_size;
    uint16_t         blocks_count;
} pn532_uid_t;

/**
 * @brief Heap-allocated result of pn532_14443_get_all_uids().
 *
 * The structure uses a flexible trailing array. Free it with free() when no
 * longer needed.
 */
typedef struct
{
    uint8_t     uids_count;
    pn532_uid_t uids[1];
} pn532_uids_array_t;

/**
 * @brief PN532 device context.
 *
 * Applications should treat this as a driver-owned handle and avoid mutating
 * fields directly. The members remain visible because the driver is split
 * across multiple translation units rather than exposing a separate private
 * wrapper type.
 */
typedef struct _pn532_t
{
    uint8_t     *send_buf;
    uint8_t     *recv_buf;
    pn532_bus_t *bus;
    gpio_num_t   irq;
    gpio_num_t   rst;
    uint16_t     timeout_ms;
    uint8_t      rf_config;
    bool         is_rf_on;
    uint8_t      inListedTag;
    bool         session_opened;
    bool         recovery_in_progress;
} pn532_t;

/** @brief Sleep helper used by the driver and available to callers building retry loops. */
void pn532_delay_ms(int ms);

/**
 * @brief Create a PN532 SPI transport handle.
 *
 * The returned handle is heap-allocated. Destroy it with pn532_bus_destroy(),
 * or pass free_bus=true to pn532_deinit().
 *
 * @param host_id SPI host that carries the PN532 device.
 * @param sck SPI clock GPIO used when initialising the host bus.
 * @param miso SPI MISO GPIO used when initialising the host bus.
 * @param mosi SPI MOSI GPIO used when initialising the host bus.
 * @param nss SPI chip-select GPIO for the PN532 device.
 * @param clock_speed_hz SPI device clock.
 * @return Newly allocated transport handle, or NULL on failure.
 */
pn532_bus_t *pn532_spi_init(         //
    spi_host_device_t host_id,       //
    gpio_num_t        sck,           //
    gpio_num_t        miso,          //
    gpio_num_t        mosi,          //
    gpio_num_t        nss,           //
    int               clock_speed_hz //
);

/**
 * @brief Create a PN532 I2C transport handle.
 *
 * The function creates an ESP-IDF I2C master bus and attaches the PN532 as a
 * device on it. If device_address is 0, PN532_I2C_DEFAULT_ADDRESS is used.
 * The returned handle is heap-allocated and owned by the caller.
 *
 * @return Newly allocated transport handle, or NULL on failure.
 */
pn532_bus_t *pn532_i2c_init(       //
    i2c_port_num_t port,           //
    gpio_num_t     scl,            //
    gpio_num_t     sda,            //
    uint16_t       device_address, //
    uint32_t       clock_speed_hz  //
);

/**
 * @brief Create a PN532 UART/HSU transport handle.
 *
 * The constructor installs and owns the UART driver for uart_num. If baud_rate
 * is non-positive, PN532_UART_DEFAULT_BAUD_RATE is used.
 *
 * @return Newly allocated transport handle, or NULL on failure.
 */
pn532_bus_t *pn532_uart_init(uart_port_t uart_num, gpio_num_t tx, gpio_num_t rx, int baud_rate);

/** @brief Destroy a transport handle created by pn532_spi_init(), pn532_i2c_init(), or pn532_uart_init(). */
void         pn532_bus_destroy(pn532_bus_t *bus);

/**
 * @brief Create and initialise a PN532 device context on top of an existing transport.
 *
 * The function allocates the pn532_t context, internal frame buffers, performs
 * a reset, reads the firmware version, and applies the runtime SAM/retry
 * configuration.
 *
 * @param bus Transport created by one of the pn532_*_init() functions.
 * @param irq Optional IRQ pin; pass GPIO_NUM_NC when unused.
 * @param rst Optional reset pin; pass GPIO_NUM_NC when unused.
 * @return Newly allocated device context, or NULL on failure.
 */
pn532_t     *pn532_init(pn532_bus_t *bus, gpio_num_t irq, gpio_num_t rst);

/**
 * @brief Free a PN532 device context.
 *
 * @param pn532 Device created by pn532_init().
 * @param free_bus When true, also destroys pn532->bus via pn532_bus_destroy().
 */
void         pn532_deinit(pn532_t *pn532, bool free_bus);

/**
 * @brief Reset the PN532 and clear target/session state.
 *
 * If rst was provided at pn532_init() time, the pin is toggled. Otherwise this
 * is a logical driver reset only.
 */
bool     pn532_reset(pn532_t *pn532);

/**
 * @brief Read the PN532 firmware identifier.
 *
 * The packed return value is PN532's four response bytes in big-endian order:
 * IC, version, revision, support.
 *
 * @return Packed firmware identifier, or 0 on failure.
 */
uint32_t pn532_get_firmware_version(pn532_t *pn532);

/** @brief Turn the RF field on or off through RFConfiguration item 0x01. */
bool pn532_set_rf_field(pn532_t *pn532, bool enabled);

/** @brief Convenience wrapper for pn532_set_rf_field(pn532, true). */
bool pn532_set_rf_on(pn532_t *pn532);

/** @brief Convenience wrapper for pn532_set_rf_field(pn532, false). */
bool pn532_set_rf_off(pn532_t *pn532);

/**
 * @brief Poll for ISO14443A targets and return their UIDs.
 *
 * The returned array is heap-allocated and must be released with free(). When
 * one or more targets are found, the first target is also opened with InSelect
 * and becomes the active PN532 target session.
 *
 * @return Heap-allocated target array, or NULL when no card was found or polling failed.
 */
pn532_uids_array_t *pn532_14443_get_all_uids(pn532_t *pn532);

/**
 * @brief Select a specific ISO14443A target by UID and open a PN532 session for it.
 *
 * The helper first tries a targeted passive-list command and falls back to an
 * untargeted scan plus UID match when necessary.
 */
bool                pn532_14443_select_by_uid(pn532_t *pn532, const pn532_uid_t *uid);

/**
 * @brief Authenticate a MIFARE Classic sector with Key A or Key B.
 *
 * For non-Classic subtypes this function returns true and performs no exchange,
 * which lets higher-level code share a single auth callback across card types.
 */
bool                pn532_14443_authenticate(   //
    pn532_t           *pn532,    //
    const uint8_t     *key,      //
    uint8_t            key_type, //
    const pn532_uid_t *uid,      //
    int                blockno   //
);

/**
 * @brief Infer card subtype, block count, and block size from ATQA/SAK.
 *
 * The helper updates uid->subtype, uid->blocks_count, and uid->block_size in
 * place and also returns the same values through the out parameters.
 */
bool pn532_14443_detect_card_type_and_capacity(pn532_uid_t *uid, uint16_t *blocks_count, uint16_t *block_size);

/**
 * @brief Compatibility wrapper mirroring the pn5180 API shape.
 *
 * The current PN532 implementation performs the same local detection as
 * pn532_14443_detect_card_type_and_capacity() and always sets
 * *needs_reselect = false.
 */
bool pn532_14443_detect_selected_card_type_and_capacity( //
    pn532_t     *pn532,                                  //
    pn532_uid_t *uid,                                    //
    uint16_t    *blocks_count,                           //
    uint16_t    *block_size,                             //
    bool        *needs_reselect                          //
);

/**
 * @brief Exchange one ISO14443-4 APDU with the currently selected Type 4 target.
 *
 * The PN532 firmware handles RATS, PCB toggling, WTX, and chaining internally;
 * callers provide only raw APDU bytes.
 *
 * @param apdu Command APDU payload.
 * @param apdu_len Command length in bytes.
 * @param rx Output buffer for the response APDU.
 * @param rx_len In: rx capacity. Out: received response size.
 */
bool pn532_14443_4_transceive(pn532_t *pn532, const uint8_t *apdu, size_t apdu_len, uint8_t *rx, size_t *rx_len);

/** @brief Issue ISO-DEP SELECT FILE by AID or file identifier. */
bool pn532_14443_4_select_file(pn532_t *pn532, const uint8_t *file_id, size_t file_id_len);

/**
 * @brief Issue ISO-DEP READ BINARY on the currently selected file.
 *
 * @param offset File offset to read from.
 * @param le Requested byte count.
 * @param buffer Output buffer.
 * @param got In: buffer capacity. Out: actual bytes returned.
 */
bool pn532_14443_4_read_binary(pn532_t *pn532, uint16_t offset, uint8_t le, uint8_t *buffer, size_t *got);