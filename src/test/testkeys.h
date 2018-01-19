#ifndef SDCPTESTKEYS_H
#define SDCPTESTKEYS_H

#include "sdcpconstants.h"

// In a real implementation, this model public key will be contained in a
// certificate. For now, there is no cert validation being done in the OS
// (test-signing must be enabled to test this feature), and so we just use the
// bare public key in place of the certificate.
extern const uint8_t g_model_pub_key[SDCP_PUBLIC_KEY_SIZE_V1];

// On the factory floor, the device public key is signed with the model private
// key. The device MUST NOT have access to the model private key. Here, the
// variable is non-const so that we can simulate removing access to it by
// zeroing it out after use.
extern uint8_t g_model_priv_key[SDCP_PRIVATE_KEY_SIZE_V1];

#endif // SDCPTESTKEYS_H
