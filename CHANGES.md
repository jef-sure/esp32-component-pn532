# Changelog

## v 0.0.2 - 2026-04-29

### Add optional IRQ-backed ready notifications

When a valid IRQ GPIO is passed to `pn532_init()`, the driver can use PN532 ready interrupts while waiting for ACK and response frames.

### Add retry tuning helpers to the public API

Exposed `pn532_set_max_retries()` and `pn532_set_passive_activation_retries()` in `pn532.h`.

### Add raw PN532 command execution helper

Exposed `pn532_execute_command()` for commands that do not yet have a dedicated typed helper.

### Restructure the simple SPI example source tree

Moved the sample source to `examples/simple/main/main.c` and updated the example component `CMakeLists.txt` to match.

### Split simple example documentation out of the root README

Moved sample-specific wiring, integration notes, and related usage details into `examples/simple/README.md`.

### Add dedicated README for examples/simple

Documented the sample folder layout, default SPI wiring, integration options, and normal `idf.py` workflow.

## v 0.0.1 - 2026-04-28

Initial import from another project
