#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sdcpclient.h"
#include "testkeys.h"
#include "helpers.h"

#define ASSERT_EQUAL(a, b) assert((a) == (b))

sdcp_keypair device_key = { 0 };
sdcp_signature model_signature = { 0 };

void factory_provision(void)
{
    // Dump the model keys
    fputs("Model and device keys:\n----------------------\n", stderr);
    print_bytes_err("pk_m", g_model_pub_key, sizeof(g_model_pub_key));
    print_bytes_err("sk_m", g_model_priv_key, sizeof(g_model_priv_key));

    // First, the device is provisioned at the factory, which
    // results in the model signature.
    fputs("\nFactory provisioning:\n---------------------\n", stderr);
    ASSERT_EQUAL(0, sdcpcli_keygen(&device_key));
    print_bytes_err("pk_d", device_key.pk, sizeof(device_key.pk));
    print_bytes_err("sk_d", device_key.sk, sizeof(device_key.sk));

    uint8_t key_hash[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_hash(device_key.pk, sizeof(device_key.pk), key_hash, sizeof(key_hash)));

    ASSERT_EQUAL(0, sdcpcli_sign_hash(
        g_model_priv_key, sizeof(g_model_priv_key),
        key_hash, sizeof(key_hash),
        &model_signature));
    print_bytes_err("s_m", (const uint8_t*)&model_signature, sizeof(model_signature));

    // The model private key is never used outside of the factory. It
    // must never be present on the device. Zero it out now.
    secure_zero_memory(g_model_priv_key, sizeof(g_model_priv_key));
}

int load_provision(const char *file)
{
    FILE *f;

    f = fopen(file, "r");

    if (!f)
        return -1;

    if (fread(&device_key, 1, sizeof(device_key), f) != sizeof(device_key))
        goto err;
    if (fread(&model_signature, 1, sizeof(model_signature), f) != sizeof(model_signature))
        goto err;

    fclose(f);

    fputs("Loaded old factory provisioning from file\n", stderr);
    print_bytes_err("pk_d", device_key.pk, sizeof(device_key.pk));
    print_bytes_err("sk_d", device_key.sk, sizeof(device_key.sk));

    return 0;

err:
    fprintf(stderr, "Could not read file (probably too short), ferror: %i\n", ferror(f));
    fclose(f);
    return -1;
}

int save_provision(const char *file)
{
    FILE *f;

    f = fopen(file, "w+");

    if (!f)
        return -1;

    if (fwrite(&device_key, 1, sizeof(device_key), f) != sizeof(device_key))
        return -1;
    if (fwrite(&model_signature, 1, sizeof(model_signature), f) != sizeof(model_signature))
        return -1;

    fclose(f);

    return 0;
}

sdcp_keypair firmware_key = { 0 };
sdcp_firmware_signature firmware_signature = { 0 };

void boot(void)
{
    // At boot-time, the bootloader measures and signs the
    // device firmware with the device private key, which is only
    // accessible to the bootloader itself.
    fputs("\nDevice bootloader:\n------------------\n", stderr);
    // Clearly bogus firmware data.
    const uint8_t firmware[] = { 'f', 'i', 'r', 'm', 'w', 'a', 'r', 'e' };
    print_bytes_err("firmware", firmware, sizeof(firmware));

    // Sign the firmware and generate the ECDH firmware key pair.
    ASSERT_EQUAL(0, sdcpcli_sign_firmware(
        device_key.sk, sizeof(device_key.sk),
        firmware, sizeof(firmware),
        &firmware_key,
        &firmware_signature));
    print_bytes_err("h_f", firmware_signature.hash, sizeof(firmware_signature.hash));
    print_bytes_err("pk_f", firmware_key.pk, sizeof(firmware_key.pk));
    print_bytes_err("sk_f", firmware_key.sk, sizeof(firmware_key.sk));
    print_bytes_err("s_d", (const uint8_t*)&firmware_signature.sig, sizeof(firmware_signature.sig));
    // Zero the device private key to ensure that the code running after
    // the bootloader does not have access to it.
    secure_zero_memory(device_key.sk, sizeof(device_key.sk));
}

sdcp_application_keys app_keys = { 0 };

void connect(void)
{
    // During the connection protocol, the host will send its public
    // ECDH key, as well as some random bytes. The client uses this
    // to do key agreement, and creates an attestation claim
    fputs("\nConnect:\n--------\n", stderr);
    uint8_t host_random[SDCP_RANDOM_SIZE_V1] = { 0 };

    if (fread(&host_random, sizeof(host_random), 1, stdin) != 1)
    {
        fputs("Could not read host random for connect\n", stderr);
        exit(2);
    }
    print_bytes_err("r_h", host_random, sizeof(host_random));

    sdcp_keypair host_key = { 0 };
    if (fread(&host_key.pk, sizeof(host_key.pk), 1, stdin) != 1)
    {
        fputs("Could not read host public key for connect\n", stderr);
        exit(2);
    }
    print_bytes_err("pk_h", host_key.pk, sizeof(host_key.pk));

    uint8_t device_random[SDCP_RANDOM_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_gen_rand(device_random, sizeof(device_random)));
    print_bytes_err("r_d", device_random, sizeof(device_random));

    uint8_t device_master_secret[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_derive_master_secret(
        host_key.pk, sizeof(host_key.pk),
        firmware_key.sk, sizeof(firmware_key.sk),
        host_random, sizeof(host_random),
        device_random, sizeof(device_random),
        device_master_secret, sizeof(device_master_secret)));
    print_bytes_err("ms", device_master_secret, sizeof(device_master_secret));

    ASSERT_EQUAL(0, sdcpcli_derive_application_keys(
        device_master_secret, sizeof(device_master_secret),
        &app_keys));

    print_bytes_err("s", app_keys.s, sizeof(app_keys.s));

    print_bytes_err("k", app_keys.k, sizeof(app_keys.k));

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
    print_bytes_err("H(c)", claim_hash, sizeof(claim_hash));

    uint8_t mac[SDCP_DIGEST_SIZE_V1] = { 0 };
    ASSERT_EQUAL(0, sdcpcli_mac_claim_hash(
        &app_keys,
        claim_hash, sizeof(claim_hash),
        mac, sizeof(mac)));
    print_bytes_err("m", mac, sizeof(mac));

    if (fwrite(&device_random, sizeof(device_random), 1, stdout) != 1)
        goto err;

    uint16_t cert_length = sizeof(g_model_pub_key);
    if (fwrite(&cert_length, sizeof(cert_length), 1, stdout) != 1)
        goto err;
    if (fwrite(&g_model_pub_key, sizeof(g_model_pub_key), 1, stdout) != 1)
        goto err;
    if (fwrite(&device_key.pk, sizeof(device_key.pk), 1, stdout) != 1)
        goto err;
    if (fwrite(&firmware_key.pk, sizeof(firmware_key.pk), 1, stdout) != 1)
        goto err;
    if (fwrite(&firmware_signature.hash, sizeof(firmware_signature.hash), 1, stdout) != 1)
        goto err;
    if (fwrite(&model_signature, sizeof(model_signature), 1, stdout) != 1)
        goto err;
    if (fwrite(&firmware_signature.sig, sizeof(firmware_signature.sig), 1, stdout) != 1)
        goto err;
    if (fwrite(mac, sizeof(mac), 1, stdout) != 1)
        goto err;
    fflush(stdout);

    return;

err:
    fputs("Could not write connect response\n", stderr);
    exit(2);
}

void reconnect(void)
{
    // Now simulate a reconnect. The host will send new random bytes for
    // the client to MAC.
    uint8_t host_random[SDCP_RANDOM_SIZE_V1] = { 0 };
    uint8_t mac[SDCP_DIGEST_SIZE_V1] = { 0 };
    fputs("\nReconnect:\n----------\n", stderr);

    if (fread(&host_random, sizeof(host_random), 1, stdin) != 1)
    {
        fputs("Could not read host random for reconnect\n", stderr);
        exit(2);
    }

    print_bytes_err("r", host_random, sizeof(host_random));

    ASSERT_EQUAL(0, sdcpcli_mac_reconnect(
        &app_keys,
        host_random, sizeof(host_random),
        mac, sizeof(mac)));
    print_bytes_err("m", mac, sizeof(mac));

    if (fwrite(&mac, sizeof(mac), 1, stdout) != 1)
    {
        fputs("Could not write MAC response for reconnect\n", stderr);
        exit(2);
    }
    fflush (stdout);
}

/* Simulate one active enrollement and always identify the last enrolled print. */
static int enrolling = 0;
static uint8_t enroll_nonce[SDCP_RANDOM_SIZE_V1] = { 0 };
static uint8_t enrolled[SDCP_RANDOM_SIZE_V1] = { 0 };

void enroll_begin(void)
{
    // Simulate an enroll begin, generate a random enroll nonce.
    fputs("\nEnrollBegin:\n----------\n", stderr);

    ASSERT_EQUAL(0, sdcpcli_gen_rand(enroll_nonce, sizeof(enroll_nonce)));
    enrolling = 1;

    print_bytes_err("nonce", enroll_nonce, sizeof(enroll_nonce));

    if (fwrite(&enroll_nonce, sizeof(enroll_nonce), 1, stdout) != 1)
    {
        fputs("Could not write enroll nonce response for enroll begin\n", stderr);
        exit(2);
    }
    fflush (stdout);
}

void enroll_commit(void)
{
    // Simulate an enroll commit, check MAC and commit.
    uint8_t mac[SDCP_DIGEST_SIZE_V1] = { 0 };

    fputs("\nEnrollCommit:\n----------\n", stderr);

    assert(enrolling);
    enrolling = 0;

    if (fread(&mac, sizeof(mac), 1, stdin) != 1)
    {
        fputs("Could not read MAC (ID) for enroll commit\n", stderr);
        exit(2);
    }

    print_bytes_err("mac", mac, sizeof(mac));

    ASSERT_EQUAL(0, sdcpcli_verify_enrollment_mac(
        &app_keys,
        enroll_nonce, sizeof(enroll_nonce),
        mac, sizeof(mac)));
    memset (enroll_nonce, 0, sizeof(enroll_nonce));
    memcpy (enrolled, mac, sizeof(enrolled));

    fputs("Enroll was successful\n", stderr);
}

void enroll_cancel(void)
{
    fputs("\EnrollCancel:\n----------\n", stderr);

    assert(enrolling);
    enrolling = 0;

    memset (enroll_nonce, 0, sizeof(enroll_nonce));

    fputs("Enroll was cancelled\n", stderr);
}

void identify(void)
{
    // Simulate an identify by simply assuming the last enrolled print was
    // matched (even if that is still all zeros).
    fputs("\nIdentify:\n----------\n", stderr);
    uint8_t nonce[SDCP_RANDOM_SIZE_V1] = { 0 };
    uint8_t mac[SDCP_DIGEST_SIZE_V1] = { 0 };

    if (fread(&nonce, sizeof(nonce), 1, stdin) != 1)
    {
        fputs("Could not read nonce for identify\n", stderr);
        exit(2);
    }

    ASSERT_EQUAL(0, sdcpcli_mac_identity(
        &app_keys,
        nonce, sizeof(nonce),
        enrolled, sizeof(enrolled),
        mac, sizeof(mac)));

    if (fwrite(&enrolled, sizeof(enrolled), 1, stdout) != 1)
    {
        fputs("Could not write identified ID\n", stderr);
        exit(2);
    }
    if (fwrite(&mac, sizeof(mac), 1, stdout) != 1)
    {
        fputs("Could not write enrollment MAC\n", stderr);
        exit(2);
    }
    fflush (stdout);
}

int main(int argc, char **argv)
{

    // Try to load provisioning from file, otherwise provision and store.
    if (argc < 2 || load_provision(argv[1]) != 0)
    {
        factory_provision();
        if (argc >= 2) {
            save_provision(argv[1]);
        }
    }

    boot();

    // We implement an extremely simple chat protocol on stdin/stdout.
    // i.e. we read a single byte, which may be:
    //  'C': Connect
    //  'R': Reconnect
    //  'E': Enroll
    //  'F': EnrollCommit ('E' + 1)
    //  'G': Enroll cancellation ('E' + 2)
    //  'I': Identify
    //  'X': Quit
    // Where identify is extremely stupid and just always returns the last
    // enrolled ID (or a zero-id).

    while (1)
    {
        int command;

        command = fgetc(stdin);
        switch (command)
        {
            case 'C':
                fputs("Received connect command\n", stderr);
                connect();
                break;

            case 'R':
                fputs("Received reconnect command\n", stderr);
                reconnect();
                break;

            case 'E':
                fputs("Received enroll begin command\n", stderr);
                enroll_begin();
                break;

            case 'F':
                fputs("Received enroll commit command\n", stderr);
                enroll_commit();
                break;

            case 'G':
                fputs("Received enroll cancellation command\n", stderr);
                enroll_cancel();
                break;

            case 'I':
                identify();
                break;

            case 'X':
                return 0;

            default:
                fprintf(stderr, "Unknown command 0x%02X, quitting\n", command);
                return 2;
        }
    }

    return 0;
}
