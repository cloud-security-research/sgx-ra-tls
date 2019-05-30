/* Code to create an extended X.509 certificate with wolfSSL. */

#define _GNU_SOURCE // for memmem()

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sgx_uae_service.h>

#ifdef RATLS_ECDSA
#include <curl/curl.h>

#include <sgx_quote_3.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "ra.h"
#include "wolfssl-ra.h"
#include "ra-attester.h"
#include "ra-attester_private.h"
#ifdef RATLS_ECDSA
#include "ecdsa-ra-attester.h"
#include "ecdsa-sample-data/real/sample_data.h"
#include "ecdsa-attestation-collateral.h"
#endif
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

#ifdef RATLS_ECDSA
/**
 * Generate RA-TLS certificate containing ECDSA-based attestation evidence.
 * 
 * @param der_crt Caller must allocate memory for certificate.
 * @param der_crt_len On entry contains the size of der_crt buffer. On return holds actual size of certificate in bytes.
 */
static
void ecdsa_generate_x509
(
    RsaKey* key,
    uint8_t* der_crt,     /* out */
    int* der_crt_len, /* in/out */
    const ecdsa_attestation_evidence_t* evidence
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

    memcpy(crt.quote, evidence->quote, evidence->quote_len);
    crt.quoteSz = evidence->quote_len;

    memcpy(crt.pckCrt, evidence->pck_crt, evidence->pck_crt_len);
    crt.pckCrtSz = evidence->pck_crt_len;

    memcpy(crt.pckSignChain, evidence->pck_sign_chain,
           evidence->pck_sign_chain_len);
    crt.pckSignChainSz = evidence->pck_sign_chain_len;

    memcpy(crt.tcbInfo, evidence->tcb_info,
           evidence->tcb_info_len);
    crt.tcbInfoSz = evidence->tcb_info_len;

    memcpy(crt.tcbSignChain, evidence->tcb_sign_chain,
           evidence->tcb_sign_chain_len);
    crt.tcbSignChainSz = evidence->tcb_sign_chain_len;

    memcpy(crt.qeIdentity, evidence->qe_identity,
           evidence->qe_identity_len);
    crt.qeIdentitySz = evidence->qe_identity_len;

    memcpy(crt.rootCaCrl, evidence->root_ca_crl,
           evidence->root_ca_crl_len);
    crt.rootCaCrlSz = evidence->root_ca_crl_len;

    memcpy(crt.pckCrl, evidence->pck_crl,
           evidence->pck_crl_len);
    crt.pckCrlSz = evidence->pck_crl_len;
    
    RNG    rng;
    wc_InitRng(&rng);
    
    int certSz = wc_MakeSelfCert(&crt, der_crt, *der_crt_len, key, &rng);
    assert(certSz > 0);
    *der_crt_len = certSz;
}
#endif

static void
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

#ifdef RATLS_ECDSA
static void binary_to_base16
(
    const uint8_t* binary,
    uint32_t binary_len,
    char* base16,
    uint32_t base16_len
)
{
    /* + 1 for terminating null byte. */
    assert(base16_len >= binary_len * 2 + 1);
    
    for (uint32_t i = 0; i < binary_len; ++i) {
        sprintf(&base16[i * 2], "%02X", binary[i]);
    }
}

static void ecdsa_get_quote_from_quote_service
(
    const sgx_report_data_t* report_data,
    uint8_t* quote,
    uint32_t* quote_len
)
{
    uint32_t quote_size = 0;
    sgx_target_info_t qe_target_info = {0, };
    int sockfd = connect_to_quote_service();
    get_target_info_from_quote_service(sockfd, &qe_target_info, &quote_size);
    assert(quote_size <= *quote_len);
    
    sgx_report_t report;
    create_report(&qe_target_info, report_data, &report);
    get_quote_from_quote_service(sockfd, &report, quote, quote_size);
    *quote_len = quote_size;
    
    close(sockfd);
}

static void ecdsa_get_quote
(
    const sgx_report_data_t* report_data,
    uint8_t* quote,
    uint32_t* quote_len
)
{
#ifndef SGX_SIMULATION
    ecdsa_get_quote_from_quote_service(report_data,
                                       quote, quote_len);
#else
    (void) report_data;
    
    assert(ecdsa_sample_data_quote_ppid_rsa3072_dat_len <= *quote_len);
    memcpy(quote, ecdsa_sample_data_quote_ppid_rsa3072_dat, ecdsa_sample_data_quote_ppid_rsa3072_dat_len);
    *quote_len = ecdsa_sample_data_quote_ppid_rsa3072_dat_len;
#endif
}

/* static void print_byte_array(FILE* f, uint8_t* data, int size) { */
/*     for (int i = 0; i < size; ++i) { */
/*         fprintf(f, "%02X", data[i]); */
/*     } */
/* } */

size_t accumulate_function(void *ptr, size_t size, size_t nmemb, void *userdata);

struct buffer_and_size {
    char* data;
    size_t len;
};

static
void parse_response_header_get_pck_cert
(
    CURL* curl,
    const char* headers,
    size_t headers_len,
    char* pck_cert_chain,
    uint32_t* pck_cert_chain_len
)
{
    const char header_tag[] = "SGX-PCK-Certificate-Issuer-Chain: ";
    char* header_begin = memmem((const char*) headers,
                             headers_len,
                             header_tag,
                             strlen(header_tag));
    if (header_begin == NULL) {
        fprintf(stderr, "HTTP headers: %.*s\n", (int) headers_len, headers);
    }
    assert(header_begin != NULL);
    header_begin += strlen(header_tag);
    char* header_end = memmem(header_begin,
                           headers_len - (header_begin - headers),
                           "\r\n",
                           strlen("\r\n"));
    assert(header_end);

    int unescaped_len;
    char* unescaped = curl_easy_unescape(curl, header_begin, header_end - header_begin, &unescaped_len);
    assert(unescaped);
    assert(unescaped_len <= (int) *pck_cert_chain_len);
    memcpy(pck_cert_chain, unescaped, unescaped_len);
    *pck_cert_chain_len = unescaped_len;
    curl_free(unescaped);
}

static
void get_pck_cert
(
    const char* url,
    const struct ecdsa_ra_tls_options* opts,
    ecdsa_attestation_evidence_t* evidence
)
{
    CURL *curl;
    CURLcode res;

    assert(NULL != url);
    
    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        /* curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); */
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    
        char buf[128];
        int rc = snprintf(buf, sizeof(buf), "Ocp-Apim-Subscription-Key: %.32s",
                          opts->subscription_key);
        assert(rc < (int) sizeof(buf));
                 
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, buf);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        struct buffer_and_size header = {(char*) malloc(1), 0};
        struct buffer_and_size body = {(char*) malloc(1), 0};
    
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, accumulate_function);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, accumulate_function);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

        /* Perform the request. */
        res = curl_easy_perform(curl);
        if (res != 0) {
            printf("curl_easy_perform= %d\n", res);
        }

        evidence->pck_sign_chain_len = sizeof(evidence->pck_sign_chain);
        parse_response_header_get_pck_cert(curl, header.data, header.len,
                                           (char*) evidence->pck_sign_chain,
                                           &evidence->pck_sign_chain_len);

        assert(sizeof(evidence->pck_crt) >= body.len);
        evidence->pck_crt_len = sizeof(evidence->pck_crt);
        memcpy(evidence->pck_crt, body.data, body.len);
        evidence->pck_crt_len = body.len;
    
        /* Check for errors */
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        curl_easy_cleanup(curl);

        free(header.data);
        free(body.data);
    }

    curl_global_cleanup();
}

static
void parse_response_header_tcb_info_cert_chain
(
    CURL* curl,
    const char* headers,
    size_t headers_len,
    char* cert_chain,
    uint32_t* cert_chain_len
)
{
    const char header_tag[] = "SGX-TCB-Info-Issuer-Chain: ";
    char* header_begin = memmem((const char*) headers,
                             headers_len,
                             header_tag,
                             strlen(header_tag));
    assert(header_begin != NULL);
    header_begin += strlen(header_tag);
    char* header_end = memmem(header_begin,
                           headers_len - (header_begin - headers),
                           "\r\n",
                           strlen("\r\n"));
    assert(header_end);

    int unescaped_len;
    char* unescaped = curl_easy_unescape(curl, header_begin, header_end - header_begin, &unescaped_len);
    assert(unescaped);
    assert((int) *cert_chain_len >= unescaped_len);
    memcpy(cert_chain, unescaped, unescaped_len);
    *cert_chain_len = unescaped_len;
}

static void curl_get_tcb_info
(
    char fmspc_base16[12],
    ecdsa_attestation_evidence_t* evidence
)
{
    /* HTTP GET for TCB info (json) evidence->tcb_info. */
    char url[256];
    int rc = snprintf(url, sizeof(url),
                      "https://api.trustedservices.intel.com/sgx/certification/v1/tcb?fmspc=%s",
                      fmspc_base16);
    assert(rc < (int) sizeof(url));

    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    
        struct buffer_and_size header = {(char*) malloc(1), 0};
        struct buffer_and_size body = {(char*) malloc(1), 0};
    
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, accumulate_function);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, accumulate_function);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

        res = curl_easy_perform(curl);
        assert(res == CURLE_OK);

        evidence->tcb_sign_chain_len = sizeof(evidence->tcb_sign_chain);
        parse_response_header_tcb_info_cert_chain(curl, header.data, header.len,
                                                  (char*) evidence->tcb_sign_chain,
                                                  &evidence->tcb_sign_chain_len);

        assert(sizeof(evidence->tcb_info) >= body.len);
        evidence->tcb_info_len = sizeof(evidence->tcb_info);
        memcpy(evidence->tcb_info, body.data, body.len);
        evidence->tcb_info_len = body.len;

        curl_easy_cleanup(curl);

        free(header.data);
        free(body.data);
    }

    curl_global_cleanup();
}

static
void http_get_tcb_info
(
    ecdsa_attestation_evidence_t* evidence,
    const struct ecdsa_ra_tls_options* opts
)
{
    assert(NULL != evidence->pck_crt);
    assert(evidence->pck_crt_len > 0);
    (void) opts;

    uint8_t pck_crt_der[2048];
    uint32_t pck_crt_der_len = sizeof(pck_crt_der);
    int bytes = wolfSSL_CertPemToDer(evidence->pck_crt, evidence->pck_crt_len,
                                     pck_crt_der, pck_crt_der_len, CERT_TYPE);
    assert(bytes > 0);
    pck_crt_der_len = (uint32_t) bytes;
    
    DecodedCert crt;

    InitDecodedCert(&crt, (byte*) pck_crt_der, pck_crt_der_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    int ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);

    /* ASN.1 OID type (0x06), length 10 bytes (0x0a), OID
       1.2.840.113741.1.13.1.4 */
    const uint8_t fmspc_oid[] = { 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04 };
    uint8_t* fmspc = memmem(crt.extensions, crt.extensionsSz,
                            fmspc_oid, sizeof(fmspc_oid));
    assert(NULL != fmspc);
    fmspc += sizeof(fmspc_oid);
    /* ASN.1 octet string (0x04), length 6 bytes (0x06) */
    fmspc += 2;
    char fmspc_base16[6 * 2 + 1];

    binary_to_base16(fmspc, 6, fmspc_base16, sizeof(fmspc_base16));
    FreeDecodedCert(&crt);

    curl_get_tcb_info(fmspc_base16, evidence);
}

static
void ecdsa_get_tcb_info
(
    ecdsa_attestation_evidence_t* evidence,
    const struct ecdsa_ra_tls_options* opts
)
{
    sgx_quote3_t* q = (sgx_quote3_t*) evidence->quote;
    assert(evidence->quote_len == sizeof(sgx_quote3_t) + q->signature_data_len);
    sgx_quote_header_t quote_header = q->header;
    assert(quote_header.version == 3);
    assert(quote_header.att_key_type == 2);

    sgx_ql_ecdsa_sig_data_t* sig_data = (sgx_ql_ecdsa_sig_data_t*) (q->signature_data);
    sgx_ql_auth_data_t* auth_data = (sgx_ql_auth_data_t*) (sig_data->auth_certification_data);
    sgx_ql_certification_data_t* cert_data_generic = (sgx_ql_certification_data_t*) (sig_data->auth_certification_data + sizeof(*auth_data) + auth_data->size);
    printf("ppid enc type= %d\n", cert_data_generic->cert_key_type);
    assert(cert_data_generic->cert_key_type == PPID_RSA3072_ENCRYPTED);
    
    /* if (cert_data_generic->cert_key_type == PPID_CLEARTEXT) { */
    /*     sgx_ql_ppid_cleartext_cert_info_t* cert_info = */
    /*         (sgx_ql_ppid_cleartext_cert_info_t*) (cert_data_generic->certification_data); */
    /*     char ppid_base16[16*2]; */
    /*     binary_to_base16(cert_info->ppid, sizeof(cert_info->ppid), */
    /*                      ppid_base16, sizeof(ppid_base16)); */
    /*     printf("PPID= %.32s\n", ppid_base16); */
    /*     assert(0); */
    /* } */
    assert(cert_data_generic->size == sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t));
    sgx_ql_ppid_rsa3072_encrypted_cert_info_t* cert_data = (sgx_ql_ppid_rsa3072_encrypted_cert_info_t*) (cert_data_generic->certification_data);

    char encrypted_ppid[786 + 1];
    char cpusvn[32 + 1];
    char pcesvn[4 + 1];
    char pceid[4 + 1];

    binary_to_base16(cert_data->enc_ppid, sizeof(cert_data->enc_ppid),
                     encrypted_ppid, sizeof(encrypted_ppid));

    binary_to_base16((uint8_t*)&cert_data->pce_info.pce_id,
                     sizeof(cert_data->pce_info.pce_id),
                     pceid, sizeof(pceid));
    
    binary_to_base16((uint8_t*)&cert_data->pce_info.pce_isv_svn,
                     sizeof(cert_data->pce_info.pce_isv_svn),
                     pcesvn, sizeof(pcesvn));

    binary_to_base16((uint8_t*)&cert_data->cpu_svn,
                     sizeof(cert_data->cpu_svn),
                     cpusvn, sizeof(cpusvn));

    /* printf("PPID=%s\nPCE ID= %s\nPCE SVN= %s\nCPU SVN= %s\n", */
    /*        encrypted_ppid, pceid, pcesvn, cpusvn); */
    
    char url[2048];
    snprintf(url, sizeof(url),
             "https://api.trustedservices.intel.com/sgx/certification/v1/pckcert?encrypted_ppid=%s&cpusvn=%s&pcesvn=%s&pceid=%s",
             encrypted_ppid, cpusvn, pcesvn, pceid);
    printf("URL= %s\n", url);
    printf("subscription_key= %.32s\n", opts->subscription_key);

    get_pck_cert(url, opts, evidence);
    http_get_tcb_info(evidence, opts);
}

static
void collect_attestation_evidence
(
    const sgx_report_data_t* report_data,
    const struct ecdsa_ra_tls_options* opts,
    ecdsa_attestation_evidence_t* evidence
)
{
    /* 1. Generate report and quote. */
    evidence->quote_len = sizeof(evidence->quote);
    ecdsa_get_quote(report_data, evidence->quote, &evidence->quote_len);
    /* 2. Get TCB Info. */
    ecdsa_get_tcb_info(evidence, opts);

    memcpy(evidence->qe_identity, qe_identity_json, qe_identity_json_len);
    evidence->qe_identity_len = qe_identity_json_len;
    memcpy(evidence->root_ca_crl, root_ca_crl_pem, root_ca_crl_pem_len);
    evidence->root_ca_crl_len = root_ca_crl_pem_len;
    memcpy(evidence->pck_crl, pck_crl_pem, pck_crl_pem_len);
    evidence->pck_crl_len = pck_crl_pem_len;
}

static void
ecdsa_wolfssl_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ecdsa_ra_tls_options* opts
)
{
    /* Generate key. */
    RsaKey genKey;
    RNG    rng;
    int    ret;

    wc_InitRng(&rng);
    wc_InitRsaKey(&genKey, 0);
    ret = wc_MakeRsaKey(&genKey, 3072, 65537, &rng);
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
    ecdsa_attestation_evidence_t evidence;

    collect_attestation_evidence(&report_data, opts, &evidence);

    ecdsa_generate_x509(&genKey, der_cert, der_cert_len, &evidence);
}

void ecdsa_create_key_and_x509
(
    uint8_t* der_key,  /* out */
    int* der_key_len,  /* in/out */
    uint8_t* der_cert, /* out */
    int* der_cert_len, /* in/out */
    const struct ecdsa_ra_tls_options* opts /* in */
)
{
    ecdsa_wolfssl_create_key_and_x509(der_key, der_key_len,
                                der_cert, der_cert_len,
                                opts);
}
#endif

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

void create_key_and_x509_pem
(
    uint8_t* pem_key,  /* out */
    int* pem_key_len,  /* in/out */
    uint8_t* pem_cert, /* out */
    int* pem_cert_len, /* in/out */
    const struct ra_tls_options* opts
)
{
    unsigned char der_key[16 * 1024] = {0, };
    int der_key_len = sizeof(der_key);
    unsigned char der_cert[16 * 1024] = {0, };
    int der_cert_len = sizeof(der_cert_len);
    int len;

    wolfssl_create_key_and_x509(der_key, &der_key_len,
                                der_cert, &der_cert_len,
                                opts);

    len = wc_DerToPem(der_key, der_key_len, pem_key, *pem_key_len, PRIVATEKEY_TYPE);
    assert(len > 0);
    *pem_key_len = len;

    len = wc_DerToPem(der_cert, der_cert_len, pem_cert, *pem_cert_len, CERT_TYPE);
    assert(len > 0);
    *pem_cert_len = len;
}
