#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "sdcpclient.h"
#include "testkeys.h"
#include "helpers.h"

#define ASSERT_EQUAL(a, b) assert((a) == (b))

int main()
{
    // Dump the model keys
    puts("Model and device keys:\n----------------------\n");
    print_bytes("pk_m", g_model_pub_key, sizeof(g_model_pub_key));
    print_bytes("sk_m", g_model_priv_key, sizeof(g_model_priv_key));

    // First, the device is provisioned at the factory, which
    // results in the model signature.
    puts("\nFactory provisioning:\n---------------------\n");
    sdcp_keypair device_key = { 0 };
    ASSERT_EQUAL(0, sdcpcli_keygen(&device_key));
    print_bytes("pk_d", device_key.pk, sizeof(device_key.pk));
    print_bytes("sk_d", device_key.sk, sizeof(device_key.sk));

    uint8_t key_hash[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_hash(device_key.pk, sizeof(device_key.pk), key_hash, sizeof(key_hash)));

    sdcp_signature model_signature = { 0 };
    ASSERT_EQUAL(0, sdcpcli_sign_hash(
        g_model_priv_key, sizeof(g_model_priv_key),
        key_hash, sizeof(key_hash),
        &model_signature));
    print_bytes("s_m", (const uint8_t*)&model_signature, sizeof(model_signature));

    // The model private key is never used outside of the factory. It
    // must never be present on the device. Zero it out now.
    secure_zero_memory(g_model_priv_key, sizeof(g_model_priv_key));

    // At boot-time, the bootloader measures and signs the
    // device firmware with the device private key, which is only
    // accessible to the bootloader itself.
    puts("\nDevice bootloader:\n------------------\n");
    // Clearly bogus firmware data.
    const uint8_t firmware[] = { 'f', 'i', 'r', 'm', 'w', 'a', 'r', 'e' };
    print_bytes("firmware", firmware, sizeof(firmware));

    // Sign the firmware and generate the ECDH firmware key pair.
    sdcp_keypair firmware_key = { 0 };
    sdcp_firmware_signature firmware_signature = { 0 };
    ASSERT_EQUAL(0, sdcpcli_sign_firmware(
        device_key.sk, sizeof(device_key.sk),
        firmware, sizeof(firmware),
        &firmware_key,
        &firmware_signature));
    print_bytes("h_f", firmware_signature.hash, sizeof(firmware_signature.hash));
    print_bytes("pk_f", firmware_key.pk, sizeof(firmware_key.pk));
    print_bytes("sk_f", firmware_key.sk, sizeof(firmware_key.sk));
    print_bytes("s_d", (const uint8_t*)&firmware_signature.sig, sizeof(firmware_signature.sig));
    // Zero the device private key to ensure that the code running after
    // the bootloader does not have access to it.
    secure_zero_memory(device_key.sk, sizeof(device_key.sk));

    // During the connection protocol, the host will send its public
    // ECDH key, as well as some random bytes. The client uses this
    // to do key agreement, and creates an attestation claim
    puts("\nConnect:\n--------\n");
    uint8_t host_random[SDCP_RANDOM_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_gen_rand(host_random, sizeof(host_random)));
    print_bytes("h_r", host_random, sizeof(host_random));

    sdcp_keypair host_key = { 0 };
    ASSERT_EQUAL(0, sdcpcli_keygen(&host_key));
    print_bytes("pk_h", host_key.pk, sizeof(host_key.pk));

    uint8_t device_random[SDCP_RANDOM_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_gen_rand(device_random, sizeof(device_random)));
    print_bytes("r_d", device_random, sizeof(device_random));

    uint8_t device_master_secret[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_derive_master_secret(
        host_key.pk, sizeof(host_key.pk),
        firmware_key.sk, sizeof(firmware_key.sk),
        host_random, sizeof(host_random),
        device_random, sizeof(device_random),
        device_master_secret, sizeof(device_master_secret)));
    print_bytes("ms", device_master_secret, sizeof(device_master_secret));

    sdcp_application_keys app_keys = { 0 };
    ASSERT_EQUAL(0, sdcpcli_derive_application_keys(
        device_master_secret, sizeof(device_master_secret),
        &app_keys));
    print_bytes("s", app_keys.s, sizeof(app_keys.s));
    print_bytes("k", app_keys.k, sizeof(app_keys.k));

    secure_zero_memory(device_master_secret, sizeof(device_master_secret));

    // Create and MAC the attestation claim. We do this in two stages
    // client-side to allow caching of the claim hash, which will remain the
    // same for this boot cycle.
    //
    // There is no support for real certificate validation yet.
    // For now, just pass in the model public key in place of the
    // ASN.1 DER encoded X509 cert.
    uint8_t claim_hash[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_hash_claim(
        g_model_pub_key, sizeof(g_model_pub_key), // Pub key in place of cert for now.
        device_key.pk, sizeof(device_key.pk),
        firmware_key.pk, sizeof(firmware_key.pk),
        &firmware_signature,
        &model_signature,
        claim_hash, sizeof(claim_hash)));
    print_bytes("H(c)", claim_hash, sizeof(claim_hash));

    uint8_t mac[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_mac_claim_hash(
        &app_keys,
        claim_hash, sizeof(claim_hash),
        mac, sizeof(mac)));
    print_bytes("m", mac, sizeof(mac));

    // Now simulate a reconnect. The host will send new random bytes for
    // the client to MAC.
    puts("\nReconnect:\n----------\n");
    ASSERT_EQUAL(0, sdcpcli_gen_rand(host_random, sizeof(host_random)));
    print_bytes("r", host_random, sizeof(host_random));

    ASSERT_EQUAL(0, sdcpcli_mac_reconnect(
        &app_keys,
        host_random, sizeof(host_random),
        mac, sizeof(mac)));
    print_bytes("m", mac, sizeof(mac));

    return 0;
}
