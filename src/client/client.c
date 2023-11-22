#include <mbedtls/md.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/cipher.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sdcpclient.h"

#define MBEDTLS_CHK(call) if((err = (call)) != 0) { goto exit; }

static void secure_zero_memory(void* ptr, size_t len)
{
    volatile uint8_t *cursor = (volatile uint8_t *)ptr;
    while (len != 0)
    {
        *cursor = 0;
        cursor++;
        len--;
    }
}

static uint32_t big_endian32(uint32_t x)
{
    uint32_t x_be = x;
#if defined(LITTLE_ENDIAN) && BYTE_ORDER == LITTLE_ENDIAN
    x_be = (x_be & 0x0000ffff) << 16 | (x_be & 0xffff0000) >> 16;
    x_be = (x_be & 0x00ff00ff) <<  8 | (x_be & 0xff00ff00) >>  8;
#endif
    return x_be;
}

int sdcpcli_gen_rand(uint8_t* rand, size_t rand_len)
{
    if (rand == NULL || rand_len == 0)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    int err = 0;

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    const char personalization[] = "sdcpcli_gen_rand";
    MBEDTLS_CHK(mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func, &entropy,
        (uint8_t*)personalization, sizeof(personalization)));

    MBEDTLS_CHK(mbedtls_ctr_drbg_random(&ctr_drbg, rand, rand_len));

exit:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return err;
}

int sdcpcli_kdf(
    const uint8_t* key, size_t key_len,
    const char* label,
    const uint8_t* context, size_t context_len,
    uint8_t* output, size_t output_len)
{
    if (key == NULL || key_len < SDCP_DIGEST_SIZE_V1 ||
        label == NULL ||
        (context == NULL && context_len > 0) ||
        output == NULL || output_len > UINT32_MAX / CHAR_BIT)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    int err = 0;
    const uint32_t n = (uint32_t)((output_len + SDCP_DIGEST_SIZE_V1 - 1) / SDCP_DIGEST_SIZE_V1);
    const uint32_t l_bits_be = big_endian32((uint32_t)output_len * 8);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    MBEDTLS_CHK(mbedtls_md_setup(
        &ctx,
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        1)); // HMAC

    MBEDTLS_CHK(mbedtls_md_hmac_starts(&ctx, key, key_len));
    for (uint32_t i = 0; i < n; ++i)
    {
        uint32_t i_be = big_endian32(i + 1);
        size_t offset = i * SDCP_DIGEST_SIZE_V1;
        size_t bytes_remaining = output_len - offset;
        uint8_t tmp[SDCP_DIGEST_SIZE_V1] = { 0 };

        // i_be || label || context || l_bits_be
        MBEDTLS_CHK(mbedtls_md_hmac_update(&ctx, (uint8_t*)&i_be, sizeof(i_be)));
        MBEDTLS_CHK(mbedtls_md_hmac_update(&ctx, (uint8_t*)label, strlen(label) + 1));
        if (context_len > 0)
        {
            MBEDTLS_CHK(mbedtls_md_hmac_update(&ctx, context, context_len));
        }
        MBEDTLS_CHK(mbedtls_md_hmac_update(&ctx, (uint8_t*)&l_bits_be, sizeof(l_bits_be)));

        MBEDTLS_CHK(mbedtls_md_hmac_finish(&ctx, tmp));
        MBEDTLS_CHK(mbedtls_md_hmac_reset(&ctx));

        memcpy(output + offset, tmp, bytes_remaining < 32 ? bytes_remaining : 32);
    }

exit:
    mbedtls_md_free(&ctx);

    return 0;
}

int sdcpcli_keygen(sdcp_keypair* keypair)
{
    if (keypair == NULL)
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    int err = 0;
    size_t olen = 0;
    const char personalization[] = "sdcpcli_keygen";

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_ecp_keypair mbedtls_keypair;
    mbedtls_ecp_keypair_init(&mbedtls_keypair);

    MBEDTLS_CHK(mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func, &entropy,
        (const uint8_t*)personalization, sizeof(personalization)));

    MBEDTLS_CHK(mbedtls_ecp_gen_key(
        MBEDTLS_ECP_DP_SECP256R1,
        &mbedtls_keypair,
        mbedtls_ctr_drbg_random, &ctr_drbg));

    MBEDTLS_CHK(mbedtls_ecp_point_write_binary(
        &mbedtls_keypair.grp, &mbedtls_keypair.Q,
        MBEDTLS_ECP_PF_UNCOMPRESSED,
        &olen, keypair->pk, sizeof(keypair->pk)));
    assert(olen == sizeof(keypair->pk));

    assert(mbedtls_mpi_size(&mbedtls_keypair.d) == sizeof(keypair->sk));
    MBEDTLS_CHK(mbedtls_mpi_write_binary(
        &mbedtls_keypair.d,
        keypair->sk, sizeof(keypair->sk)));

exit:
    mbedtls_ecp_keypair_free(&mbedtls_keypair);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return err;
}

int sdcpcli_hash(const uint8_t* data, size_t len, uint8_t* hash, size_t hash_len)
{
    if (data == NULL || len == 0 || hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, len, hash);
}

int sdcpcli_sign_hash(
    const uint8_t* sk, size_t sk_len,
    const uint8_t* hash, size_t hash_len,
    sdcp_signature* signature)
{
    if (sk == NULL || sk_len < SDCP_PRIVATE_KEY_SIZE_V1 ||
        hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1 ||
        signature == NULL)
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    int err = 0;

    mbedtls_mpi d, r, s;
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    MBEDTLS_CHK(mbedtls_mpi_read_binary(&d, sk, SDCP_PRIVATE_KEY_SIZE_V1));
    MBEDTLS_CHK(mbedtls_ecp_check_privkey(&grp, &d));

    MBEDTLS_CHK(mbedtls_ecdsa_sign_det(
        &grp, &r, &s, &d,
        hash, SDCP_DIGEST_SIZE_V1,
        MBEDTLS_MD_SHA256));

    MBEDTLS_CHK(mbedtls_mpi_write_binary(&r, signature->r, sizeof(signature->r)));
    MBEDTLS_CHK(mbedtls_mpi_write_binary(&s, signature->s, sizeof(signature->s)));

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);

    return err;
}

int sdcpcli_verify(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* hash, size_t hash_len,
    const sdcp_signature* signature)
{
    if (pk == NULL || pk_len < SDCP_PUBLIC_KEY_SIZE_V1 ||
        hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1 ||
        signature == NULL)
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    int err = 0;

    mbedtls_ecp_point q;
    mbedtls_ecp_point_init(&q);

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    MBEDTLS_CHK(mbedtls_ecp_point_read_binary(&grp, &q, pk, pk_len));
    MBEDTLS_CHK(mbedtls_ecp_check_pubkey(&grp, &q));

    MBEDTLS_CHK(mbedtls_mpi_read_binary(&r, signature->r, sizeof(signature->r)));
    MBEDTLS_CHK(mbedtls_mpi_read_binary(&s, signature->s, sizeof(signature->r)));

    MBEDTLS_CHK(mbedtls_ecdsa_verify(&grp, hash, hash_len, &q, &r, &s));

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);

    return err;
}

int sdcpcli_secret_agreement(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* sk, size_t sk_len,
    uint8_t* secret, size_t secret_len)
{
    if (pk == NULL || pk_len < SDCP_PUBLIC_KEY_SIZE_V1 ||
        sk == NULL || sk_len < SDCP_PRIVATE_KEY_SIZE_V1 ||
        secret == NULL || secret_len < SDCP_CURVE_FIELD_SIZE_V1)
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    int err = 0;

    mbedtls_ecp_point q;
    mbedtls_ecp_point_init(&q);

    mbedtls_mpi d, z;
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);

    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    const char personalization[] = "sdcpcli_secret_agreement";

    MBEDTLS_CHK(mbedtls_ecp_point_read_binary(&grp, &q, pk, SDCP_PUBLIC_KEY_SIZE_V1));
    MBEDTLS_CHK(mbedtls_ecp_check_pubkey(&grp, &q));

    MBEDTLS_CHK(mbedtls_mpi_read_binary(&d, sk, SDCP_PRIVATE_KEY_SIZE_V1));
    MBEDTLS_CHK(mbedtls_ecp_check_privkey(&grp, &d));

    MBEDTLS_CHK(mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func, &entropy,
        (const uint8_t*)personalization, sizeof(personalization)));

    MBEDTLS_CHK(mbedtls_ecdh_compute_shared(
        &grp, &z, &q, &d,
        mbedtls_ctr_drbg_random, &ctr_drbg));

    assert(mbedtls_mpi_size(&z) == SDCP_CURVE_FIELD_SIZE_V1);
    MBEDTLS_CHK(mbedtls_mpi_write_binary(&z, secret, SDCP_CURVE_FIELD_SIZE_V1));

exit:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);

    return err;
}

int sdcpcli_derive_master_secret(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* rh, size_t rh_len,
    const uint8_t* rd, size_t rd_len,
    uint8_t* ms, size_t ms_len)
{
    if (rh == NULL || rh_len < SDCP_RANDOM_SIZE_V1 ||
        rd == NULL || rd_len < SDCP_RANDOM_SIZE_V1)
    {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    int err = 0;

    uint8_t r[SDCP_RANDOM_SIZE_V1 * 2] = { 0 };
    memcpy(r, rh, SDCP_RANDOM_SIZE_V1);
    memcpy(r + SDCP_RANDOM_SIZE_V1, rd, SDCP_RANDOM_SIZE_V1);

    uint8_t pms[SDCP_CURVE_FIELD_SIZE_V1] = { 0 };
    MBEDTLS_CHK(sdcpcli_secret_agreement(
        pk, pk_len,
        sk, sk_len,
        pms, sizeof(pms)));

    MBEDTLS_CHK(sdcpcli_kdf(
        pms, sizeof(pms),
        SDCP_LABEL_MASTER_SECRET,
        r, sizeof(r),
        ms, ms_len));

exit:
    secure_zero_memory(r, sizeof(r));
    secure_zero_memory(pms, sizeof(pms));

    return err;
}

int sdcpcli_derive_application_keys(
    const uint8_t* ms, size_t ms_len,
    sdcp_application_keys* keys)
{
    return sdcpcli_kdf(
        ms, ms_len,
        SDCP_LABEL_APPLICATION_KEYS,
        NULL, 0,
        (uint8_t*)keys, sizeof(*keys));
}

int sdcpcli_sign_firmware(
    const uint8_t* skd, size_t skd_len,
    const uint8_t* fw, size_t fw_len,
    sdcp_keypair* fw_keypair,
    sdcp_firmware_signature* fw_sig)
{
    if (fw == NULL || fw_len == 0 || fw_sig == NULL)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    int err = 0;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    uint8_t md[SDCP_DIGEST_SIZE_V1] = { 0 };

    // Two-byte {0xC0, 0x01} header
    const uint8_t header[2] = {
        (uint8_t)(SDCP_DEVICE_SIGNATURE_HEADER_V1 >> 8),
        (uint8_t)(SDCP_DEVICE_SIGNATURE_HEADER_V1 & 0xff)
    };

    MBEDTLS_CHK(sdcpcli_keygen(fw_keypair));

    MBEDTLS_CHK(mbedtls_md_setup(
        &ctx,
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        0));

    MBEDTLS_CHK(mbedtls_md_starts(&ctx));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, fw, fw_len));
    MBEDTLS_CHK(mbedtls_md_finish(&ctx, fw_sig->hash));

    MBEDTLS_CHK(mbedtls_md_starts(&ctx));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, header, sizeof(header)));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, fw_sig->hash, sizeof(fw_sig->hash)));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, fw_keypair->pk, sizeof(fw_keypair->pk)));
    MBEDTLS_CHK(mbedtls_md_finish(&ctx, md));

    // Sig(sk_d, H(C001||H(fw)||pk_f))
    MBEDTLS_CHK(sdcpcli_sign_hash(skd, skd_len, md, sizeof(md), &fw_sig->sig));

exit:
    mbedtls_md_free(&ctx);

    return err;
}

int sdcpcli_hash_claim(
    const uint8_t* cert, size_t cert_len,
    const uint8_t* pkd, size_t pkd_len,
    const uint8_t* pkf, size_t pkf_len,
    const sdcp_firmware_signature* sd,
    const sdcp_signature* sm,
    uint8_t* hash, size_t hash_len)
{
    if (cert == NULL || cert_len == 0 ||
        pkd == NULL || pkd_len < SDCP_PUBLIC_KEY_SIZE_V1 ||
        pkf == NULL || pkf_len < SDCP_PUBLIC_KEY_SIZE_V1 ||
        sd == NULL || sm == NULL ||
        hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    int err = 0;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    MBEDTLS_CHK(mbedtls_md_setup(
        &ctx,
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        0));

    // c <- (cert_m, pk_d, pk_f, h_f, s_m, s_d)
    MBEDTLS_CHK(mbedtls_md_starts(&ctx));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, cert, cert_len));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, pkd, SDCP_PUBLIC_KEY_SIZE_V1));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, pkf, SDCP_PUBLIC_KEY_SIZE_V1));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, sd->hash, sizeof(sd->hash)));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, (const uint8_t*)sm, sizeof(*sm)));
    MBEDTLS_CHK(mbedtls_md_update(&ctx, (const uint8_t*)&sd->sig, sizeof(sd->sig)));
    MBEDTLS_CHK(mbedtls_md_finish(&ctx, hash));

exit:
    mbedtls_md_free(&ctx);

    return err;

}

typedef struct { const uint8_t* ptr; size_t len; } mac_data;

static int mac_with_label(
    const sdcp_application_keys* keys,
    const char* label,
    const mac_data* data, size_t count,
    uint8_t* mac, size_t mac_len)
{
    if (keys == NULL || label == NULL ||
        (data == NULL && count > 0) ||
        mac == NULL || mac_len < SDCP_DIGEST_SIZE_V1)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    int err = 0;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    MBEDTLS_CHK(mbedtls_md_setup(
        &ctx,
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        1)); // HMAC

    MBEDTLS_CHK(mbedtls_md_hmac_starts(&ctx, keys->s, sizeof(keys->s)));
    MBEDTLS_CHK(mbedtls_md_hmac_update(&ctx, (const uint8_t*)label, strlen(label) + 1));
    for (size_t i = 0; i < count; ++i)
    {
        MBEDTLS_CHK(mbedtls_md_hmac_update(&ctx, data[i].ptr, data[i].len));
    }
    MBEDTLS_CHK(mbedtls_md_hmac_finish(&ctx, mac));

exit:
    mbedtls_md_free(&ctx);

    return err;
}

int sdcpcli_mac_claim_hash(
    const sdcp_application_keys* keys,
    const uint8_t* hash, size_t hash_len,
    uint8_t* mac, size_t mac_len)
{
    if (hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    mac_data data[1] = { 0 };
    data[0].ptr = hash;
    data[0].len = SDCP_DIGEST_SIZE_V1;

    return mac_with_label(
        keys,
        SDCP_LABEL_CONNECT,
        data, sizeof(data) / sizeof(data[0]),
        mac, mac_len);
}

int sdcpcli_mac_reconnect(
    const sdcp_application_keys* keys,
    const uint8_t* rand, size_t rand_len,
    uint8_t* mac, size_t mac_len)
{
    if (rand == NULL || rand_len < SDCP_RANDOM_SIZE_V1)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    mac_data data[1] = { 0 };
    data[0].ptr = rand;
    data[0].len = SDCP_RANDOM_SIZE_V1;

    return mac_with_label(
        keys,
        SDCP_LABEL_RECONNECT,
        data, sizeof(data) / sizeof(data[0]),
        mac, mac_len);
}

int sdcpcli_mac_encrypted_sample(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* enc, size_t enc_len,
    uint8_t* mac, size_t mac_len)
{
    if (nonce == NULL || nonce_len == 0 ||
        iv == NULL || iv_len < SDCP_ENCRYPTION_BLOCK_SIZE_V1 ||
        enc == NULL || enc_len == 0)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    mac_data data[3] = { 0 };
    data[0].ptr = nonce;
    data[0].len = nonce_len;
    data[1].ptr = iv;
    data[1].len = SDCP_ENCRYPTION_BLOCK_SIZE_V1;
    data[2].ptr = enc;
    data[2].len = enc_len;

    return mac_with_label(
        keys,
        SDCP_LABEL_SAMPLE,
        data, sizeof(data) / sizeof(data[0]),
        mac, mac_len);
}

int sdcpcli_mac_identity(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* id, size_t id_len,
    uint8_t* mac, size_t mac_len)
{
    if (nonce == NULL || nonce_len == 0 ||
        id == NULL || id_len == 0)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    mac_data data[2] = { 0 };
    data[0].ptr = nonce;
    data[0].len = nonce_len;
    data[1].ptr = id;
    data[1].len = id_len;

    return mac_with_label(
        keys,
        SDCP_LABEL_IDENTIFY,
        data, sizeof(data) / sizeof(data[0]),
        mac, mac_len);
}

int sdcpcli_verify_enrollment_mac(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* mac, size_t mac_len)
{
    if (nonce == NULL || nonce_len == 0 ||
        mac == NULL || mac_len < SDCP_DIGEST_SIZE_V1)
    {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    mac_data data[1] = { 0 };
    data[0].ptr = nonce;
    data[0].len = nonce_len;

    uint8_t verify_mac[SDCP_DIGEST_SIZE_V1] = { 0 };
    mac_with_label(
        keys,
        SDCP_LABEL_ENROLL,
        data, sizeof(data) / sizeof(data[0]),
        verify_mac, sizeof(verify_mac));
    
    int diff = 0;
    for (size_t i = 0; i < sizeof(verify_mac); i++)
    {
        diff |= mac[i] ^ verify_mac[i];
    }

    return diff == 0 ? 0 : MBEDTLS_ERR_MD_BAD_INPUT_DATA;
}

static int generate_iv(
    const sdcp_application_keys* keys,
    uint32_t* iv_seed,
    uint8_t* iv, size_t iv_len)
{
    if (keys == NULL || iv_seed == NULL ||
        iv == NULL || iv_len < SDCP_ENCRYPTION_BLOCK_SIZE_V1)
    {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    int err = 0;
    const char iv_label[] = "iv";
    uint32_t seed = big_endian32(*iv_seed++);

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    MBEDTLS_CHK(mbedtls_md_setup(
        &ctx,
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        1)); // HMAC

    MBEDTLS_CHK(mbedtls_md_hmac_starts(&ctx, keys->s, sizeof(keys->s)));
    MBEDTLS_CHK(mbedtls_md_hmac_update(&ctx, (const uint8_t*)iv_label, strlen(iv_label) + 1));
    MBEDTLS_CHK(mbedtls_md_hmac_update(&ctx, (const uint8_t*)&seed, sizeof(seed)));
    MBEDTLS_CHK(mbedtls_md_hmac_finish(&ctx, iv));

exit:
    mbedtls_md_free(&ctx);

    return err;
}

int sdcpcli_encrypt_sample(
    const sdcp_application_keys* keys,
    uint32_t* iv_seed,
    const uint8_t* sample, size_t sample_len,
    uint8_t* iv, size_t iv_len,
    uint8_t* enc, size_t enc_len, size_t* enc_olen)
{
    if (keys == NULL || iv_seed == NULL ||
        sample == NULL || sample_len == 0 ||
        iv == NULL || iv_len < SDCP_ENCRYPTION_BLOCK_SIZE_V1 ||
        enc == NULL || enc_olen == NULL)
    {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (enc_len < sample_len + SDCP_ENCRYPTION_BLOCK_SIZE_V1)
    {
        *enc_olen = sample_len + SDCP_ENCRYPTION_BLOCK_SIZE_V1;
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    int err = 0;

    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);

    uint8_t iv_copy[SDCP_ENCRYPTION_BLOCK_SIZE_V1] = { 0 };

    MBEDTLS_CHK(mbedtls_cipher_setup(
        &ctx,
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC)));

    assert(mbedtls_cipher_get_key_bitlen(&ctx) == sizeof(keys->k) * CHAR_BIT);
    MBEDTLS_CHK(mbedtls_cipher_setkey(
        &ctx,
        keys->k, sizeof(keys->k) * CHAR_BIT,
        MBEDTLS_ENCRYPT));

    MBEDTLS_CHK(generate_iv(keys, iv_seed, iv, iv_len));
    memcpy(iv_copy, iv, sizeof(iv_copy));

    *enc_olen = enc_len;
    MBEDTLS_CHK(mbedtls_cipher_crypt(
        &ctx,
        iv_copy, sizeof(iv_copy),
        sample, sample_len,
        enc, enc_olen));

exit:
    mbedtls_cipher_free(&ctx);

    return err;
}
