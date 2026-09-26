# Simple Example

`examples/simple` is a PN532 SPI demo laid out as an ESP-IDF example project. It reads the PN532 firmware ID, polls for ISO14443A cards, prints UIDs, tries NDEF parsing first, and falls back to raw dumps when needed.

## Folder Layout

```text
examples/simple/
|- CMakeLists.txt
\- main/
   |- CMakeLists.txt
   \- main.c
```

This folder now uses the standard ESP-IDF project layout: a project-level `CMakeLists.txt` plus a `main` component.

## Component Resolution

Inside this repository, the example automatically adds the repository root as a local ESP-IDF component and accounts for the checkout directory name.

When copying the example into another application, add `jef-sure/pn532` through ESP-IDF Component Manager or place the component under `components/pn532`. The `main/CMakeLists.txt` defaults to `REQUIRES pn532` outside this checkout.

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
- distinguishes no-card, timeout, and other polling failures through the typed polling API
- supports up to two cards per scan
- prints discovered UIDs
- attempts an NDEF read first
- falls back to raw dumps by card family when NDEF is unavailable

The sample always runs the NDEF read path first and falls back to a raw dump when that read reports no NDEF data.
Each loop explicitly follows `poll -> release -> RF off`, so it can be adapted to alternate between multiple readers without leaving the previous reader's field active. See the root README for a two-PN532 shared-SPI example using distinct NSS pins.

## Build And Run

Once the `pn532` component is available to the example project, use the normal workflow:

```sh
cd examples/simple
idf.py build
idf.py flash monitor
```

For the driver API and transport helpers, see the repository root [README](../../README.md).