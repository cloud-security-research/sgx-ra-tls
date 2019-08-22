#!/bin/bash

set -x

if [[ -z "$ECDSA_SUBSCRIPTION_KEY" ]] && ( [[ -z "$SPID" ]] || [[ -z "$EPID_SUBSCRIPTION_KEY" ]] ); then
    echo "Either SPID and EPID_SUBSCRIPTION_KEY or ECDSA_SUBSCRIPTION_KEY is required!"
    exit 1
fi

if ( [[ ! -z "$SPID" ]] && [[ -z "$EPID_SUBSCRIPTION_KEY" ]] ) || \
   ( [[ -z "$SPID" ]] && [[ ! -z "$EPID_SUBSCRIPTION_KEY" ]] ); then
    echo "For EPID, Both SPID and EPID_SUBSCRIPTION_KEY must be set!"
    exit 1
fi

# the SPID may be 16 bytes long, but sgx_spid_t only takes 8 bytes
SPID=$(echo $SPID | cut -c1-16)

cat <<HEREDOC
#include "ra-attester.h"

struct ra_tls_options my_ra_tls_options = {
    // SPID format is "0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00"
    .spid = {{"$SPID"}},
    .quote_type = SGX_UNLINKABLE_SIGNATURE,
    .ias_server = "api.trustedservices.intel.com/sgx/dev",
    // EPID_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = "$EPID_SUBSCRIPTION_KEY"
};

struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options = {
    // ECDSA_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = "$ECDSA_SUBSCRIPTION_KEY"
};
HEREDOC
