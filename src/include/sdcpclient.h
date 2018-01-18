#ifndef SDCPCLIENT_H
#define SDCPCLIENT_H

#include <stdint.h>
#include "sdcpconstants.h"

#ifdef __cplusplus
extern "C" {
#endif

int sdcpcli_gen_rand(uint8_t* rand, size_t rand_len);

int sdcpcli_kdf(
    const uint8_t* key, size_t key_len,
    const char* label,
    const uint8_t* context, size_t context_len,
    uint8_t* output, size_t output_len);

int sdcpcli_keygen(sdcp_keypair* keypair);

int sdcpcli_hash(
    const uint8_t* data, size_t len,
    uint8_t* hash, size_t hash_len);

int sdcpcli_sign_hash(
    const uint8_t* sk, size_t sk_len,
    const uint8_t* hash, size_t hash_len,
    sdcp_signature* signature);

int sdcpcli_verify(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* hash, size_t hash_len,
    const sdcp_signature* signature);

int sdcpcli_secret_agreement(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* sk, size_t sk_len,
    uint8_t* secret, size_t secret_len);

int sdcpcli_derive_master_secret(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* rh, size_t rh_len,
    const uint8_t* rd, size_t rd_len,
    uint8_t* ms, size_t ms_len);

int sdcpcli_derive_application_keys(
    const uint8_t* ms, size_t ms_len,
    sdcp_application_keys* keys);

int sdcpcli_sign_firmware(
    const uint8_t* skd, size_t skd_len,
    const uint8_t* fw, size_t fw_len,
    sdcp_keypair* fw_keypair,
    sdcp_firmware_signature* fw_sig);

int sdcpcli_hash_claim(
    const uint8_t* cert, size_t cert_len,
    const uint8_t* pkd, size_t pkd_len,
    const uint8_t* pkf, size_t pkf_len,
    const sdcp_firmware_signature* sd,
    const sdcp_signature* sm,
    uint8_t* hash, size_t hash_len);

int sdcpcli_mac_claim_hash(
    const sdcp_application_keys* keys,
    const uint8_t* hash, size_t hash_len,
    uint8_t* mac, size_t mac_len);

int sdcpcli_mac_reconnect(
    const sdcp_application_keys* keys,
    const uint8_t* rand, size_t rand_len,
    uint8_t* mac, size_t mac_len);

int sdcpcli_mac_encrypted_sample(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* enc, size_t enc_len,
    uint8_t* mac, size_t mac_len);

int sdcpcli_verify_enrollment_mac(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* mac, size_t mac_len);

int sdcpcli_mac_identity(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* id, size_t id_len,
    uint8_t* mac, size_t mac_len);

int sdcpcli_encrypt_sample(
    const sdcp_application_keys* keys,
    uint32_t* iv_seed,
    const uint8_t* sample, size_t sample_len,
    uint8_t* iv, size_t iv_len,
    uint8_t* enc, size_t enc_len, size_t* enc_olen);

#ifdef __cplusplus
}
#endif

#endif // SDCPCLIENT_H
