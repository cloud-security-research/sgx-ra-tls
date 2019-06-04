#include "ra-attester.h"

struct ra_tls_options my_ra_tls_options = {
    .spid = {{0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00}},
    .quote_type = SGX_UNLINKABLE_SIGNATURE,
    .ias_server = "api.trustedservices.intel.com/sgx/dev",
    .subscription_key = "0123456789abcdef0123456789abcdef"
};

struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options = {
    .subscription_key = "0123456789abcdef0123456789abcdef"
};
