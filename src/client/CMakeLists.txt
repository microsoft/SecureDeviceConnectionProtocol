find_package(mbedTLS REQUIRED)
include_directories(${MBEDTLS_INCLUDE_DIR})

add_library(sdcpcli STATIC client.c)
target_link_libraries(sdcpcli  ${MBEDCRYPTO_LIBRARY})
