#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "sdcpclient.h"

#define ASSERT_EQUAL(a, b) assert((a) == (b))

/*
   Just a bogus certificate for use in this test code:

   -----BEGIN CERTIFICATE-----
   MIICAjCCAaegAwIBAgIJAJ5KZU4S6q0VMAoGCCqGSM49BAMCMF0xCzAJBgNVBAYT
   AlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHUmVkbW9uZDESMBAGA1UECgwJTWlj
   cm9zb2Z0MRswGQYDVQQDDBJGaW5nZXJwcmludCBTYW1wbGUwHhcNMTcwOTE2MDUx
   NDExWhcNMjcwOTE0MDUxNDExWjBdMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0Ex
   EDAOBgNVBAcMB1JlZG1vbmQxEjAQBgNVBAoMCU1pY3Jvc29mdDEbMBkGA1UEAwwS
   RmluZ2VycHJpbnQgU2FtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExess
   JN4IpN2c/ULFvFYQJ31JIRHxUb8zrXGtlSVAHQDZMgl2w8g5gPqyedBNH8n0GW2k
   1oovO2iRGJryMb9QiKNQME4wHQYDVR0OBBYEFJJEz3A3Hn5hxxqA1wZtIEJxYsHT
   MB8GA1UdIwQYMBaAFJJEz3A3Hn5hxxqA1wZtIEJxYsHTMAwGA1UdEwQFMAMBAf8w
   CgYIKoZIzj0EAwIDSQAwRgIhALg1ThM0f468AmNj2scHzfEL0RuMF+23IvY2vwpY
   mnYTAiEAkl2h4OvkOoX+xrXkatS4za0adKNgBHuUT5pWsj88rxM=
   -----END CERTIFICATE-----
*/
const uint8_t g_model_pub_key[SDCP_PUBLIC_KEY_SIZE_V1] = {
    SEC1_UNCOMPRESSED_POINT_HEADER,
    0xc5, 0xeb, 0x2c, 0x24, 0xde, 0x08, 0xa4, 0xdd,
    0x9c, 0xfd, 0x42, 0xc5, 0xbc, 0x56, 0x10, 0x27,
    0x7d, 0x49, 0x21, 0x11, 0xf1, 0x51, 0xbf, 0x33,
    0xad, 0x71, 0xad, 0x95, 0x25, 0x40, 0x1d, 0x00,
    0xd9, 0x32, 0x09, 0x76, 0xc3, 0xc8, 0x39, 0x80,
    0xfa, 0xb2, 0x79, 0xd0, 0x4d, 0x1f, 0xc9, 0xf4,
    0x19, 0x6d, 0xa4, 0xd6, 0x8a, 0x2f, 0x3b, 0x68,
    0x91, 0x18, 0x9a, 0xf2, 0x31, 0xbf, 0x50, 0x88
};

const uint8_t g_device_pub_key[SDCP_PUBLIC_KEY_SIZE_V1] = {
    SEC1_UNCOMPRESSED_POINT_HEADER,
    0xbb, 0x93, 0x0c, 0x86, 0xee, 0xc3, 0x51, 0xa0,
    0xcd, 0x10, 0xb5, 0x7c, 0x15, 0x5d, 0x7a, 0x67,
    0x86, 0x73, 0x01, 0x37, 0xcf, 0x8c, 0x7e, 0x12,
    0xf9, 0x85, 0xfa, 0xf7, 0x55, 0xda, 0x7d, 0xd0,
    0xcb, 0x44, 0xb6, 0x30, 0x5d, 0x8d, 0x8e, 0x3e,
    0xf3, 0xda, 0xd5, 0x1f, 0x91, 0x54, 0x2e, 0x87,
    0xdf, 0x93, 0x1d, 0x55, 0xb0, 0x8e, 0xeb, 0xa2,
    0xcb, 0x10, 0x52, 0xbe, 0x78, 0xd5, 0xe6, 0xa5
};

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

static void print_bytes(const char* label, const uint8_t* bytes, size_t len)
{
    printf("%s:", label);
    for (size_t i = 0; i < len; ++i)
    {
        if ((i % 32) == 0)
        {
            printf("\n  ");
        }
        printf("%02x", bytes[i]);
    }
    putc('\n', stdout);
}

void factory_provisioning(sdcp_signature* model_signature)
{
    // On the factory floor, the device public key is signed with
    // the model private key. The device MUST NOT have access to the
    // model private key.
    uint8_t model_priv_key[SDCP_PRIVATE_KEY_SIZE_V1] = {
        0x54, 0x96, 0x11, 0x1c, 0x96, 0x5e, 0xf4, 0x1c,
        0x9c, 0xf9, 0x1e, 0x54, 0xb3, 0x8d, 0x71, 0x4b,
        0x4e, 0x7d, 0x7c, 0x48, 0x2d, 0xcb, 0x34, 0xa3,
        0xec, 0x5e, 0x72, 0x65, 0xcf, 0x6e, 0xc8, 0x00
    };

    uint8_t keyHash[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_hash(g_device_pub_key, sizeof(g_device_pub_key), keyHash, sizeof(keyHash)));

    ASSERT_EQUAL(0, sdcpcli_sign_hash(
        model_priv_key, sizeof(model_priv_key),
        keyHash, sizeof(keyHash),
        model_signature));

    secure_zero_memory(model_priv_key, sizeof(model_priv_key));
}

void bootloader(sdcp_keypair* firmware_key, sdcp_firmware_signature* firmware_signature)
{
    // The bootloader is the only piece that has access to the
    // device private key.
    uint8_t device_priv_key[SDCP_PRIVATE_KEY_SIZE_V1] = {
        0x5d, 0xfc, 0xd4, 0xc3, 0x2b, 0x65, 0xc7, 0xc7,
        0x8b, 0x71, 0xb2, 0x2e, 0x06, 0xf6, 0xf8, 0x75,
        0xc3, 0xaf, 0x82, 0xdd, 0xec, 0x10, 0xb1, 0x87,
        0xc6, 0xe5, 0x75, 0x85, 0x71, 0x66, 0xfd, 0x2e
    };

    const uint8_t firmware[] = { 'f', 'i', 'r', 'm', 'w', 'a', 'r', 'e' };
    ASSERT_EQUAL(0, sdcpcli_sign_firmware(
        device_priv_key, sizeof(device_priv_key),
        firmware, sizeof(firmware),
        firmware_key,
        firmware_signature));

    // Zero the device private key to ensure that the code running after
    // the bootloader does not have access to it.
    secure_zero_memory(device_priv_key, sizeof(device_priv_key));
}

void secure_connection(
    const uint8_t* host_pub_key,
    const uint8_t* host_random,
    const sdcp_keypair* firmware_key,
    const sdcp_firmware_signature* firmware_signature,
    const sdcp_signature* model_signature,
    uint8_t* device_random,
    sdcp_application_keys* device_keys,
    uint8_t* claim_hash,
    uint8_t* claim_mac)
{
    // Device generates random bytes of its own, and derives the master secret
    ASSERT_EQUAL(0, sdcpcli_gen_rand(device_random, SDCP_RANDOM_SIZE_V1));

    uint8_t device_master_secret[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_derive_master_secret(
        host_pub_key, SDCP_PUBLIC_KEY_SIZE_V1,
        firmware_key->sk, sizeof(firmware_key->sk),
        host_random, SDCP_RANDOM_SIZE_V1,
        device_random, SDCP_RANDOM_SIZE_V1,
        device_master_secret, sizeof(device_master_secret)));

    // Device generates application keys
    ASSERT_EQUAL(0, sdcpcli_derive_application_keys(
        device_master_secret, sizeof(device_master_secret),
        device_keys));

    secure_zero_memory(device_master_secret, sizeof(device_master_secret));

    // Create and MAC the attestation claim. We do this in two stages
    // client-side to allow caching of the claim hash, which will remain the
    // same for this boot cycle.
    ASSERT_EQUAL(0, sdcpcli_hash_claim(
        g_model_pub_key, sizeof(g_model_pub_key), // TODO: Model certificate
        g_device_pub_key, sizeof(g_device_pub_key),
        firmware_key->pk, sizeof(firmware_key->pk),
        firmware_signature,
        model_signature,
        claim_hash, SDCP_DIGEST_SIZE_V1));

    ASSERT_EQUAL(0, sdcpcli_mac_claim_hash(
        device_keys,
        claim_hash, SDCP_DIGEST_SIZE_V1,
        claim_mac, SDCP_DIGEST_SIZE_V1));
}

void reconnect(
    const uint8_t* host_rand,
    const sdcp_application_keys* device_keys,
    uint8_t* reconnect_mac)
{
    ASSERT_EQUAL(0, sdcpcli_mac_reconnect(
        device_keys,
        host_rand, SDCP_RANDOM_SIZE_V1,
        reconnect_mac, SDCP_DIGEST_SIZE_V1));
}

int main()
{
    // First, the device is provisioned at the factory, which
    // results in the model signature.
    sdcp_signature model_signature;
    factory_provisioning(&model_signature);
    print_bytes("model signature", (const uint8_t*)&model_signature, sizeof(model_signature));

    // At boot-time, the bootloader measures and signes the
    // device firmware with the device private key, which is only
    // accessible to the bootloader itself.
    sdcp_keypair firmware_key;
    sdcp_firmware_signature firmware_signature;
    bootloader(&firmware_key, &firmware_signature);
    print_bytes("firmware key: pk", firmware_key.pk, sizeof(firmware_key.pk));
    print_bytes("firmware key: sk", firmware_key.sk, sizeof(firmware_key.sk));
    print_bytes("firmware signature: hash", firmware_signature.hash, sizeof(firmware_signature.hash));
    print_bytes("firmware signature: sig", (const uint8_t*)&firmware_signature.sig, sizeof(firmware_signature.sig));

    sdcp_keypair host_key;
    ASSERT_EQUAL(0, sdcpcli_keygen(&host_key));
    print_bytes("host ecdsa: pk", host_key.pk, sizeof(host_key.pk));

    uint8_t host_random[SDCP_RANDOM_SIZE_V1];
    ASSERT_EQUAL(0, sdcpcli_gen_rand(host_random, SDCP_RANDOM_SIZE_V1));
    print_bytes("host random", host_random, sizeof(host_random));

    // During the connection protocol, the host will send its public
    // ECDSA key, as well as some random bytes. The client uses this
    // to do key agreement, and creates an attestation claim
    uint8_t device_random[SDCP_RANDOM_SIZE_V1];
    sdcp_application_keys device_keys;
    uint8_t claim_hash[SDCP_DIGEST_SIZE_V1];
    uint8_t claim_mac[SDCP_DIGEST_SIZE_V1];
    secure_connection(
        host_key.pk,
        host_random,
        &firmware_key,
        &firmware_signature,
        &model_signature,
        device_random,
        &device_keys,
        claim_hash,
        claim_mac);
    print_bytes("device random", device_random, sizeof(device_random));
    print_bytes("device keys: s", device_keys.s, sizeof(device_keys.s));
    print_bytes("device keys: k", device_keys.k, sizeof(device_keys.k));
    print_bytes("claim hash", claim_hash, sizeof(claim_hash));
    print_bytes("claim MAC", claim_mac, sizeof(claim_mac));

    return 0;
}
