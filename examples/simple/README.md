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

## Make pn532 Available

Before building the example directly from `examples/simple`, make the `pn532` component available to the project in one of these ways:

1. Add an example-local `idf_component.yml` that depends on `jef-sure/pn532` and uses `override_path: ../../` while developing inside this repository.
2. Build the example in an ESP-IDF workspace where `pn532` is already available as a local component, for example under `components/pn532`.
3. Copy `main/main.c` and `main/CMakeLists.txt` into another ESP-IDF application.

If you reuse the sample `main/CMakeLists.txt`, keep `REQUIRES pn532` so the example links against this driver.

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

Once the `pn532` component is available to the example project, use the normal workflow:

```sh
cd examples/simple
idf.py build
idf.py flash monitor
```

For the driver API and transport helpers, see the repository root [README](../../README.md).