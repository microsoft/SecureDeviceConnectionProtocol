#ifndef SDCPCONSTANTS_H
#define SDCPCONSTANTS_H

#include <stdint.h>

#define SDCP_RANDOM_SIZE_V1           32
#define SDCP_DIGEST_SIZE_V1           32 // SHA256
#define SDCP_CURVE_FIELD_SIZE_V1      32 // P256
#define SDCP_PUBLIC_KEY_SIZE_V1       65 // 0x04||x||y
#define SDCP_PRIVATE_KEY_SIZE_V1      32 // log_2(n)/8
#define SDCP_SIGNATURE_SIZE_V1        64 // r||s
#define SDCP_ENCRYPTION_BLOCK_SIZE_V1 16 // AES
#define SDCP_ENCRYPTION_KEY_SIZE_V1   32 // AES256

#define SEC1_UNCOMPRESSED_POINT_HEADER 0x04

// Two-byte header for the device signature: {0xC0, 0x01}
#define SDCP_DEVICE_SIGNATURE_HEADER_V1 ((uint16_t)0xC001)

#define SDCP_LABEL_MASTER_SECRET    "master secret"
#define SDCP_LABEL_APPLICATION_KEYS "application keys"
#define SDCP_LABEL_CONNECT          "connect"
#define SDCP_LABEL_RECONNECT        "reconnect"
#define SDCP_LABEL_SAMPLE           "sample"
#define SDCP_LABEL_ENROLL           "enroll"
#define SDCP_LABEL_IDENTIFY         "identify"

typedef struct {
    uint8_t pk[SDCP_PUBLIC_KEY_SIZE_V1];
    uint8_t sk[SDCP_PRIVATE_KEY_SIZE_V1];
} sdcp_keypair;

typedef struct {
    uint8_t r[SDCP_CURVE_FIELD_SIZE_V1];
    uint8_t s[SDCP_CURVE_FIELD_SIZE_V1];
} sdcp_signature;

typedef struct {
    uint8_t s[SDCP_DIGEST_SIZE_V1];
    uint8_t k[SDCP_ENCRYPTION_KEY_SIZE_V1];
} sdcp_application_keys;

typedef struct {
    uint8_t hash[SDCP_DIGEST_SIZE_V1];
    sdcp_signature sig;
} sdcp_firmware_signature;

#endif // SDCPCONSTANTS_H
