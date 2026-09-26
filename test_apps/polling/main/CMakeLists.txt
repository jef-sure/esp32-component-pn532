set(PN532_COMPONENT pn532)
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../../include/pn532.h")
    set(PN532_COMPONENT esp32-component-pn532)
endif()

idf_component_register(
    SRCS "test_pn532_polling.c"
    REQUIRES ${PN532_COMPONENT} unity
    PRIV_INCLUDE_DIRS "../../../src"
)
