# Simple Example

`examples/simple` is a PN532 SPI demo component for an existing ESP-IDF application. It reads the PN532 firmware ID, polls for ISO14443A cards, prints UIDs, tries NDEF parsing first, and falls back to raw dumps when needed.

## Folder Layout

```text
examples/simple/
|- CMakeLists.txt
\- main/
   \- main.c
```

This folder is an app-component fragment, not a full `idf.py create-project` tree.

## Integrate It Into An App

Add this repository to your application as the `pn532` component, either locally under `components/pn532` or through ESP-IDF Component Manager.

Use the sample in one of these ways:

1. Copy `examples/simple` into a separate component directory in your application, for example `components/pn532_simple`, and build it unchanged.
2. Copy `main/main.c` into your application's `main` component and adapt the source path in your own `CMakeLists.txt`.

If you reuse the sample `CMakeLists.txt`, keep `REQUIRES pn532` so the component links against this driver.

## Default SPI Wiring

The sample configures the PN532 for SPI on these ESP32 GPIOs:

- `SCK`: GPIO 18
- `MISO`: GPIO 19
- `MOSI`: GPIO 23
- `NSS`: GPIO 5
- `IRQ`: not used (`GPIO_NUM_NC`)
- `RST`: not used (`GPIO_NUM_NC`)

Update the `PN532_PIN_*`, `PN532_SPI_HOST_ID`, and `PN532_SPI_CLOCK_HZ` enum constants at the top of `main/main.c` to match your board.

If you wire the PN532 IRQ line, set `PN532_PIN_IRQ` to a valid GPIO so the driver can use IRQ-ready notifications instead of transport polling. Leave it as `GPIO_NUM_NC` when IRQ is not connected.

`PN532_SPI_CLOCK_HZ` can be set up to 5 MHz, but that rate is not always reliable depending on the board, wiring, and module quality. The sample defaults to 1 MHz as a compromise that works in most setups.

## What The Sample Does

- initializes the PN532 over SPI
- reads and logs the PN532 firmware identifier
- polls for ISO14443A cards every 250 ms
- supports up to two cards per scan
- prints discovered UIDs
- attempts an NDEF read first
- falls back to raw dumps by card family when NDEF is unavailable

The sample always runs the NDEF read path first and falls back to a raw dump when that read reports no NDEF data.

## Build And Run

Once the example is inside an ESP-IDF application, use the normal workflow:

```sh
idf.py build
idf.py flash monitor
```

For the driver API and transport helpers, see the repository root [README](../../README.md).