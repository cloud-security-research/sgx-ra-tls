/* Code to create an extended X.509 certificate with wolfSSL. */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sgx_uae_service.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "ra.h"
#include "wolfssl-ra.h"
#include "wolfssl-ra-attester.h"
#include "ra-attester.h"
#include "ra_private.h"

/**
 * Caller must allocate memory for certificate.
 * 
 * @param der_crt_len On entry contains the size of der_crt buffer. On return holds actual size of certificate in bytes.
 */
static
void generate_x509
(
    RsaKey* key,
    uint8_t* der_crt,     /* out */
    int* der_crt_len, /* in/out */
    const attestation_verification_report_t* attn_report
)
{
    Cert crt;
    wc_InitCert(&crt);

    strncpy(crt.subject.country, "US", CTC_NAME_SIZE);
    strncpy(crt.subject.state, "OR", CTC_NAME_SIZE);
    strncpy(crt.subject.locality, "Hillsboro", CTC_NAME_SIZE);
    strncpy(crt.subject.org, "Intel Inc.", CTC_NAME_SIZE);
    strncpy(crt.subject.unit, "Intel Labs", CTC_NAME_SIZE);
    strncpy(crt.subject.commonName, "SGX rocks!", CTC_NAME_SIZE);
    strncpy(crt.subject.email, "webmaster@intel.com", CTC_NAME_SIZE);

    memcpy(crt.iasAttestationReport, attn_report->ias_report,
           attn_report->ias_report_len);
    crt.iasAttestationReportSz = attn_report->ias_report_len;

    memcpy(crt.iasSigCACert, attn_report->ias_sign_ca_cert,
           attn_report->ias_sign_ca_cert_len);
    crt.iasSigCACertSz = attn_report->ias_sign_ca_cert_len;

    memcpy(crt.iasSigCert, attn_report->ias_sign_cert,
           attn_report->ias_sign_cert_len);
    crt.iasSigCertSz = attn_report->ias_sign_cert_len;

    memcpy(crt.iasSig, attn_report->ias_report_signature,
           attn_report->ias_report_signature_len);
    crt.iasSigSz = attn_report->ias_report_signature_len;

    RNG    rng;
    wc_InitRng(&rng);
    
    int certSz = wc_MakeSelfCert(&crt, der_crt, *der_crt_len, key, &rng);
    assert(certSz > 0);
    *der_crt_len = certSz;
}

void
wolfssl_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ra_tls_options* opts
)
{
    /* Generate key. */
    RsaKey genKey;
    RNG    rng;
    int    ret;

    wc_InitRng(&rng);
    wc_InitRsaKey(&genKey, 0);
    ret = wc_MakeRsaKey(&genKey, 2048, 65537, &rng);
    assert(ret == 0);

    uint8_t der[4096];
    int  derSz = wc_RsaKeyToDer(&genKey, der, sizeof(der));
    assert(derSz >= 0);
    assert(derSz <= (int) *der_key_len);

    *der_key_len = derSz;
    memcpy(der_key, der, derSz);

    /* Generate certificate */
    sgx_report_data_t report_data = {0, };
    sha256_rsa_pubkey(report_data.d, &genKey);
    attestation_verification_report_t attestation_report;

    do_remote_attestation(&report_data, opts, &attestation_report);

    generate_x509(&genKey, der_cert, der_cert_len,
                  &attestation_report);
}

#ifdef WOLFSSL_SGX
time_t XTIME(time_t* tloc) {
    time_t x = 1512498557; /* Dec 5, 2017, 10:29 PDT */
    if (tloc) *tloc = x;
    return x;
}

time_t mktime(struct tm* tm) {
    (void) tm;
    assert(0);
    return (time_t) 0;
}
#endif

void create_key_and_x509
(
    uint8_t* der_key,  /* out */
    int* der_key_len,  /* in/out */
    uint8_t* der_cert, /* out */
    int* der_cert_len, /* in/out */
    const struct ra_tls_options* opts /* in */
)
{
    wolfssl_create_key_and_x509(der_key, der_key_len,
                                der_cert, der_cert_len,
                                opts);
}
