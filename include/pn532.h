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
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

/** @brief Default 7-bit PN532 I2C address in ESP-IDF's left-shifted form. */
#define PN532_I2C_DEFAULT_ADDRESS (0x24)

/** @brief Default HSU baud rate used when uart_init() receives a non-positive baud. */
#define PN532_UART_DEFAULT_BAUD_RATE (115200)

/** @brief ACK timeout in milliseconds applied by pn532_execute_command(). */
#define PN532_ACK_TIMEOUT_MS (50)

/** @brief Default RF settle delay in milliseconds after pn532_set_rf_off(). */
#define PN532_RF_SETTLE_DELAY_MS (20)

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
 * The UID, target number (Tg), ATQA, and SAK come directly from PN532 polling
 * responses. Tg is valid while the current RF/list context remains active and
 * lets pn532_14443_select_by_uid() issue InSelect without polling again.
 * subtype, block_size, and blocks_count are filled by the card-type detection
 * helpers.
 */
typedef struct
{
    uint8_t          uid[10];
    int8_t           uid_length;
    uint8_t          sak;
    pn532_nfc_type_t subtype;
    uint8_t          tg; /**< PN532 logical target number from InListPassiveTarget. */
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

/** @brief Typed outcome of an ISO14443A poll. */
typedef enum
{
    PN532_POLL_FOUND = 0,
    PN532_POLL_NO_TARGET,
    PN532_POLL_TRANSPORT_ERROR,
    PN532_POLL_TIMEOUT,
    PN532_POLL_PROTOCOL_ERROR,
    PN532_POLL_NO_MEMORY,
    PN532_POLL_INVALID_ARGUMENT
} pn532_poll_status_t;

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
    uint8_t      *send_buf;
    uint8_t      *recv_buf;
    pn532_bus_t  *bus;
    gpio_num_t    irq;
    gpio_num_t    rst;
    uint16_t      timeout_ms;
    uint16_t      ack_timeout_ms;     /**< ACK wait budget per command; 0 waits forever. */
    uint16_t      rf_settle_delay_ms; /**< Pause applied after RF off before the next poll. */
    uint8_t       rf_config;
    bool          is_rf_on;
    uint8_t       inListedTag;
    bool          session_opened;
    uint8_t       last_command_status;
    QueueHandle_t irq_queue;     /**< Set when IRQ ISR is installed; NULL otherwise. */
    bool          isr_installed; /**< True when this device owns a GPIO ISR handler on irq. */
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
void pn532_bus_destroy(pn532_bus_t *bus);

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
pn532_t *pn532_init(pn532_bus_t *bus, gpio_num_t irq, gpio_num_t rst);

/**
 * @brief Free a PN532 device context.
 *
 * @param pn532 Device created by pn532_init().
 * @param free_bus When true, also destroys pn532->bus via pn532_bus_destroy().
 */
void pn532_deinit(pn532_t *pn532, bool free_bus);

/**
 * @brief Reset the PN532 and clear target/session state.
 *
 * If rst was provided at pn532_init() time, the pin is toggled. Otherwise this
 * is a logical driver reset only.
 */
bool pn532_reset(pn532_t *pn532);

/**
 * @brief Fully re-initialise a wedged PN532 without recreating the transport.
 *
 * Runs the abort procedure, resets target/session state, re-applies the
 * SAM/retry runtime configuration, verifies the firmware version, and leaves
 * the RF field off. Use this instead of a pn532_deinit()/pn532_init() cycle
 * after repeated ACK timeouts or transport errors.
 *
 * @return true when every recovery step succeeded.
 */
bool pn532_recover(pn532_t *pn532);

/**
 * @brief Read the PN532 firmware identifier.
 *
 * The packed return value is PN532's four response bytes in big-endian order:
 * IC, version, revision, support.
 *
 * @return Packed firmware identifier, or 0 on failure.
 */
uint32_t pn532_get_firmware_version(pn532_t *pn532);

/** @brief Decoded payload of the GetGeneralStatus command (UM0701-02).
 *
 * Raw layout: `Err Field NbTg [Tg BrRx BrTx Type]{NbTg} SAMstatus` — a
 * variable-length list with one 4-byte entry per logical target (max 2)
 * followed by the SAM status byte.
 */
typedef struct
{
    uint8_t error;         /**< Last error code seen by the PN532 firmware. */
    bool    field_present; /**< External RF field detected (Field bit 0). */
    uint8_t targets_count; /**< Number of logical targets reported by NbTg. */
    struct
    {
        uint8_t tg;    /**< Logical target number. */
        uint8_t br_rx; /**< Reception baud rate (0x00 = 106 kbps, 0x01 = 212, 0x02 = 424, 0x03 = 847). */
        uint8_t br_tx; /**< Transmission baud rate, same encoding as br_rx. */
        uint8_t type;  /**< Modulation type (0x00 = ISO/IEC 14443-3A / MIFARE). */
    } targets[2];      /**< Per-target entries; valid for indexes < targets_count. */
    uint8_t sam_status;     /**< Trailing SAM status byte. */
    bool    sam_status_valid; /**< True when the reply carried the trailing SAM byte. */
} pn532_general_status_t;

/**
 * @brief Read the PN532 general status (GetGeneralStatus, command 0x04).
 *
 * Decodes the raw UM0701-02 response payload: the last firmware error code,
 * external RF field presence, the number of detected logical targets with
 * their per-target baud rates and modulation types, and the trailing SAM
 * status byte. Useful as a cheap health probe after transport failures or
 * to inspect what the PN532 still holds listed without recycling the field.
 *
 * @param pn532 Device context.
 * @param status Output structure filled on success.
 * @return true when the status frame was received and decoded.
 */
bool pn532_get_general_status(pn532_t *pn532, pn532_general_status_t *status);

/** @brief Turn the RF field on or off through RFConfiguration item 0x01. */
bool pn532_set_rf_field(pn532_t *pn532, bool enabled);

/** @brief Convenience wrapper for pn532_set_rf_field(pn532, true). */
bool pn532_set_rf_on(pn532_t *pn532);

/** @brief Convenience wrapper for pn532_set_rf_field(pn532, false). */
bool pn532_set_rf_off(pn532_t *pn532);

/**
 * @brief Release the currently listed PN532 target with InRelease.
 *
 * The function is a no-op that returns true when no target is listed. On a
 * successful command, the active target and session state are cleared.
 * Call this before turning the RF field off when ending an active session.
 *
 * @return true when no target was active or InRelease was accepted; false on
 *         command or transport failure.
 */
bool pn532_release_target(pn532_t *pn532);

/**
 * @brief Soft-deselect the currently selected target with InDeselect.
 *
 * Unlike pn532_release_target(), this keeps the target listed by the PN532 so
 * a later pn532_in_select()/pn532_14443_select_by_uid() can reactivate it
 * without a field restart. Sending InDeselect puts an ISO14443-4 target into
 * HALT. When no target is listed the function is a no-op returning true.
 *
 * @return true when the target was deselected or none was listed.
 */
bool pn532_deselect_target(pn532_t *pn532);

/**
 * @brief Configure the per-command ACK timeout.
 *
 * The PN532 sends its ACK within a few milliseconds; when no ACK arrives
 * within this budget the transport is considered dead and the command fails
 * fast instead of consuming the full response timeout. The NXP TAMA reference
 * uses 10 ms; the driver default is PN532_ACK_TIMEOUT_MS (50 ms) to cover
 * slow bus clocking.
 *
 * @param ack_timeout_ms ACK wait budget in milliseconds; 0 waits forever.
 */
void pn532_set_ack_timeout(pn532_t *pn532, uint16_t ack_timeout_ms);

/**
 * @brief Configure the settle delay applied after RF off.
 *
 * After pn532_set_rf_off() the driver waits this long before the next
 * InListPassiveTarget so a card sitting in HALT powers down and answers the
 * next activation cleanly. The default PN532_RF_SETTLE_DELAY_MS was measured
 * on hardware with a static card and a 250 ms two-reader poll cycle.
 *
 * @param delay_ms Settle delay in milliseconds; 0 disables the delay.
 */
void pn532_set_rf_settle_delay(pn532_t *pn532, uint16_t delay_ms);

/**
 * @brief Configure the PN532 retry counters for ATR, PSL, and passive activation.
 *
 * Wraps RFConfiguration item 0x05 (MaxRetries). Use 0x00 to disable retries
 * (single attempt) and 0xFF for unlimited retries. Default values applied at
 * pn532_init() time are 0xFF / 0x01 / 0x05.
 */
bool pn532_set_max_retries(pn532_t *pn532, uint8_t max_rty_atr, uint8_t max_rty_psl,
                           uint8_t max_rty_passive_activation);

/**
 * @brief Set the passive-activation retry count (RFConfiguration item 5, third byte).
 *
 * 0x00 means "try once" (fastest probe), 0xFF means "retry forever", and any
 * value in between sets a finite retry count. ATR and PSL retries are left at
 * their defaults (0xFF and 0x01).
 */
bool pn532_set_passive_activation_retries(pn532_t *pn532, uint8_t max_retries);

/**
 * @brief Issue a raw PN532 command and read the matching response frame.
 *
 * This is the low-level escape hatch behind every higher-level helper in the
 * driver. The host->PN532 framing (preamble, length, TFI, DCS, postamble) is
 * built internally; callers supply only the command code and its parameter
 * bytes. The response payload returned here strips the TFI and the response
 * code byte, so the first byte is the command-specific status / first data
 * byte as documented in UM0701-02.
 *
 * Use this for PN532 commands not exposed by a dedicated helper (e.g.
 * WriteRegister, ReadRegister, RFRegulationTest, GetGeneralStatus,
 * Diagnose, GPIO control). For ISO14443A polling and ISO14443-4 transceive,
 * prefer the typed helpers in this header.
 *
 * @param pn532 Device context.
 * @param command PN532 command code (0x02 for GetFirmwareVersion, etc.).
 * @param params Command parameter bytes, or NULL when @p params_len is 0.
 * @param params_len Length of @p params in bytes.
 * @param response Optional output buffer for the response payload.
 * @param response_len In: capacity of @p response. Out: bytes written.
 *                    Required when @p response is non-NULL. May be NULL when
 *                    the caller does not need the payload (the command must
 *                    still produce a valid response frame for this to return
 *                    true).
 * @param timeout_ms Response-phase timeout in milliseconds. The ACK phase
 *                   always uses pn532->ack_timeout_ms (see
 *                   pn532_set_ack_timeout()). 0 means wait indefinitely.
 *
 * @return true on success. On false, the response buffer contents are
 *         undefined; @p *response_len is set to the required size if the
 *         buffer was too small.
 */
bool pn532_execute_command(pn532_t *pn532, uint8_t command, const uint8_t *params, size_t params_len, uint8_t *response,
                           size_t *response_len, uint16_t timeout_ms);

/**
 * @brief Exchange raw ISO14443 bits with the currently activated target via
 *        InCommunicateThru (command 0x42).
 *
 * Unlike pn532_execute_command(), which talks to the PN532 itself, and the
 * DEP/MIFARE-wrapped pn532_in_data_exchange(), this helper forwards @p data
 * verbatim over the RF interface: the firmware sends the bits as-is and
 * returns the raw target reply. Use it for non-standard cards and commands
 * outside the MIFARE / ISO14443-4 tables. The response status byte is checked
 * against ERROR_MASK; MI-chained raw replies are drained and concatenated the
 * same way as pn532_in_data_exchange().
 *
 * @param pn532 Device context.
 * @param data Raw bytes to transmit over RF.
 * @param data_len Length of @p data in bytes.
 * @param response Optional output buffer for the raw target reply.
 * @param response_len In: capacity of @p response. Out: received size.
 * @param timeout_ms Response-phase timeout in milliseconds.
 * @return true on success. On false with a too-small buffer, @p *response_len
 *         carries the required size.
 */
bool pn532_in_communicate_thru(pn532_t *pn532, const uint8_t *data, size_t data_len, uint8_t *response,
                               size_t *response_len, uint16_t timeout_ms);

/**
 * @brief Poll for ISO14443A targets with an explicit typed outcome.
 *
 * Before each InListPassiveTarget this ends a previously active target session
 * with InRelease and switches the RF field off, matching the NXP polling
 * sequence. The list command restarts the field but does not open a target
 * session. Call pn532_14443_select_by_uid() before reading a discovered card.
 *
 * @param status Optional output status. May be NULL when the caller only needs
 *               the legacy nullable result.
 * @return Heap-allocated UID array for PN532_POLL_FOUND, otherwise NULL.
 */
pn532_uids_array_t *pn532_14443_get_all_uids_ex(pn532_t *pn532, pn532_poll_status_t *status);

/**
 * @brief Poll for ISO14443A targets and return their UIDs.
 *
 * The returned array is heap-allocated and must be released with free(). This
 * function does not select a target or open a target session.
 *
 * This compatibility wrapper calls pn532_14443_get_all_uids_ex() without a
 * status output. New code should use that function to distinguish no card,
 * timeout, transport failure, and successful discovery.
 *
 * @return Heap-allocated target array, or NULL when no card was found or polling failed.
 */
pn532_uids_array_t *pn532_14443_get_all_uids(pn532_t *pn532);

/**
 * @brief Select a specific ISO14443A target by UID and open a PN532 session for it.
 *
 * When the UID came from the current poll and its Tg is still valid, the helper
 * selects that target directly. Otherwise it performs a targeted passive-list
 * command and falls back to an untargeted scan plus UID match when necessary.
 */
bool pn532_14443_select_by_uid(pn532_t *pn532, const pn532_uid_t *uid);

/**
 * @brief Authenticate a MIFARE Classic sector with Key A or Key B.
 *
 * For non-Classic subtypes this function returns true and performs no exchange,
 * which lets higher-level code share a single auth callback across card types.
 */
bool pn532_14443_authenticate(   //
    pn532_t           *pn532,    //
    const uint8_t     *key,      //
    uint8_t            key_type, //
    const pn532_uid_t *uid,      //
    int                blockno   //
);

/**
 * @brief Read one block or page window from the currently selected memory-mapped ISO14443A tag.
 *
 * This mirrors the pn5180 14443 surface for selected Classic and Type 2 style
 * cards. For Classic, blockno addresses one 16-byte block. For Type 2 tags,
 * READ from one page returns 16 bytes covering four consecutive pages.
 */
bool pn532_14443_block_read(pn532_t *pn532, int blockno, uint8_t *buffer, size_t buffer_len);

/**
 * @brief Write one block or page on the currently selected memory-mapped ISO14443A tag.
 *
 * buffer_len >= 16 issues the Classic 16-byte WRITE command. buffer_len >= 4
 * issues the Type 2 / Ultralight 4-byte page write.
 *
 * @return 0 on success, -1 on invalid arguments, -2 on exchange failure.
 */
int pn532_14443_block_write(pn532_t *pn532, int blockno, const uint8_t *buffer, size_t buffer_len);

/**
 * @brief Infer card subtype, block count, and block size from ATQA/SAK.
 *
 * The helper updates uid->subtype, uid->blocks_count, and uid->block_size in
 * place and also returns the same values through the out parameters. When the
 * SAK is not recognised, subtype is left as PN532_MIFARE_UNKNOWN and the
 * geometry outputs are set to 0.
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
 * callers provide only raw APDU bytes. Select a target first with
 * pn532_14443_select_by_uid(). If a listed target remains but its session was
 * deselected, this function issues InSelect before exchanging the APDU.
 *
 * @param apdu Command APDU payload.
 * @param apdu_len Command length in bytes. The PN532 target byte and extended
 *                 host-frame overhead must also fit in PN532_MAX_BUF_SIZE;
 *                 with the current buffer size, at most 267 APDU bytes fit.
 * @param rx Output buffer for the response APDU.
 * @param rx_len In: rx capacity. Out: received response size.
 */
bool pn532_14443_4_transceive(pn532_t *pn532, const uint8_t *apdu, size_t apdu_len, uint8_t *rx, size_t *rx_len);

/** @brief Common ISO 7816-4 response status words. */
#define PN532_APDU_SW_SUCCESS           0x9000u
#define PN532_APDU_SW_WRONG_LENGTH      0x6700u
#define PN532_APDU_SW_WRONG_P1P2        0x6A86u
#define PN532_APDU_SW_INS_NOT_SUPPORTED 0x6D00u
#define PN532_APDU_SW_CLA_NOT_SUPPORTED 0x6E00u

/** @brief Zero-copy representation of a short ISO 7816-4 command APDU. */
typedef struct
{
    uint8_t        cla;
    uint8_t        ins;
    uint8_t        p1;
    uint8_t        p2;
    const uint8_t *data;
    size_t         data_len;
    bool           has_le;
    uint16_t       le; /**< Decoded Le; an encoded short Le of 0 is reported as 256. */
} pn532_apdu_command_t;

/** @brief Zero-copy representation of an ISO 7816-4 response APDU. */
typedef struct
{
    const uint8_t *data;
    size_t         data_len;
    uint8_t        sw1;
    uint8_t        sw2;
} pn532_apdu_response_t;

/**
 * @brief Parse a short ISO 7816-4 command APDU without allocating memory.
 *
 * Supports cases 1, 2S, 3S, and 4S. Extended-length APDUs are rejected. The
 * data member points into buffer and remains valid only while buffer is valid.
 *
 * @return ESP_OK on success, ESP_ERR_NOT_SUPPORTED for an extended-length
 *         APDU, or ESP_ERR_INVALID_ARG for invalid or malformed input.
 */
esp_err_t pn532_apdu_parse_command(const uint8_t *buffer, size_t length, pn532_apdu_command_t *command);

/**
 * @brief Build a response APDU as [data...][SW1][SW2] in caller-owned memory.
 * @return ESP_OK on success, ESP_ERR_NO_MEM when buffer is too small, or
 *         ESP_ERR_INVALID_ARG for invalid arguments.
 */
esp_err_t pn532_apdu_build_response(uint8_t *buffer, size_t buffer_size, const uint8_t *data, size_t data_len,
                                    uint8_t sw1, uint8_t sw2, size_t *response_len);

/**
 * @brief Parse a response APDU in caller-owned memory without allocation.
 * @return ESP_OK on success or ESP_ERR_INVALID_ARG when fewer than two bytes
 *         are available or an argument is NULL.
 */
esp_err_t pn532_apdu_parse_response(const uint8_t *buffer, size_t length, pn532_apdu_response_t *response);

/** @brief Return SW1 and SW2 as a single 16-bit status word, or 0 for NULL. */
uint16_t pn532_apdu_get_status(const pn532_apdu_response_t *response);

/** @brief Issue ISO-DEP SELECT FILE by AID or file identifier. */
bool pn532_14443_4_select_file(pn532_t *pn532, const uint8_t *file_id, size_t file_id_len);

/**
 * @brief Issue ISO-DEP READ BINARY on the currently selected file.
 *
 * @param offset File offset to read from.
 * @param le Encoded short Le; 0 requests 256 bytes.
 * @param buffer Output buffer.
 * @param got In: buffer capacity. Out: actual bytes returned.
 */
bool pn532_14443_4_read_binary(pn532_t *pn532, uint16_t offset, uint8_t le, uint8_t *buffer, size_t *got);