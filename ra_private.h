/* Interface to do remote attestation against Intel Attestation
   Service. Two implementations exist: (1) sgxsdk-ra-attester_* to be
   used with the SGX SDK. (2) nonsdk-ra-attester.c to be used with
   Graphene-SGX. */

#ifndef _RA_PRIVATE_H
#define _RA_PRIVATE_H

void do_remote_attestation(sgx_report_data_t* report_data,
                           const struct ra_tls_options* opts,
                           attestation_verification_report_t* r);

#endif
