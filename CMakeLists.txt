idf_component_register(
    SRCS "src/pn532.c"
         "src/pn532-mifare.c"
         "src/pn532-14443.c"
         "src/pn532-ndef.c"
         "src/pn532-bus-spi.c"
         "src/pn532-bus-i2c.c"
         "src/pn532-bus-uart.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_gpio esp_driver_i2c esp_driver_spi esp_driver_uart esp_timer
    PRIV_REQUIRES freertos log
)