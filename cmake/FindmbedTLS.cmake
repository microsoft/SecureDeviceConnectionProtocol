# On Windows, installing mbedTLS places it in "/Program Files/mbed TLS",
# so pass the "mbed TLS" suffix while searching.
find_path(MBEDTLS_INCLUDE_DIR mbedtls/version.h
          PATH_SUFFIXES "mbed TLS/include")
find_library(MBEDCRYPTO_LIBRARY mbedcrypto
             PATH_SUFFIXES "mbed TLS/lib")
mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDCRYPTO_LIBRARY)
