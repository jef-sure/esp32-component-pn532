# IDF 5.3 split "driver" into esp_driver_*; since IDF 6 "driver" no longer re-exports them.
if(IDF_VERSION_MAJOR GREATER 5 OR (IDF_VERSION_MAJOR EQUAL 5 AND IDF_VERSION_MINOR GREATER_EQUAL 3))
    set(pn532_driver_requires esp_driver_gpio esp_driver_i2c esp_driver_spi esp_driver_uart)
else()
    set(pn532_driver_requires driver)
endif()

idf_component_register(
    SRCS "src/pn532.c"
         "src/pn532-mifare.c"
         "src/pn532-14443.c"
         "src/pn532-apdu.c"
         "src/pn532-ndef.c"
         "src/pn532-bus-spi.c"
         "src/pn532-bus-i2c.c"
         "src/pn532-bus-uart.c"
    INCLUDE_DIRS "include"
    REQUIRES ${pn532_driver_requires} esp_timer
    PRIV_REQUIRES freertos log
)