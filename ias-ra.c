#define _GNU_SOURCE // for memmem()

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include <openssl/evp.h> // for base64 encode/decode

#include <stdint.h>

#include <sgx_report.h>

#include "ra.h"
#include "ra-attester.h"
#include "ias-ra.h"

struct buffer_and_size {
    char* data;
    size_t len;
};

size_t accumulate_function(void *ptr, size_t size, size_t nmemb, void *userdata) {
    struct buffer_and_size* s = (struct buffer_and_size*) userdata;
    s->data = (char*) realloc(s->data, s->len + size * nmemb);
    assert(s->data != NULL);
    memcpy(s->data + s->len, ptr, size * nmemb);
    s->len += size * nmemb;
    
    return size * nmemb;
}

static const char pem_marker_begin[] = "-----BEGIN CERTIFICATE-----";
static const char pem_marker_end[] = "-----END CERTIFICATE-----";

/* Takes a PEM as input. Strips the PEM header/footer and removes
   newlines (\n). Result is a base64-encoded DER. */
static
void pem_to_base64_der(
    const char* pem,
    uint32_t pem_len,
    char* der,
    uint32_t* der_len,
    uint32_t der_max_len
)
{
    assert(strncmp((char*) pem, pem_marker_begin, strlen(pem_marker_begin)) == 0);
    assert(strncmp((char*) pem + pem_len - strlen(pem_marker_end),
                   pem_marker_end, strlen(pem_marker_end)) == 0);
    
    uint32_t out_len = 0;
    const char* p = pem + strlen(pem_marker_begin);
    for (uint32_t i = 0;
         i < pem_len - strlen(pem_marker_begin) - strlen(pem_marker_end);
         ++i) {
        if (p[i] == '\n') continue;
        assert(out_len <= der_max_len);
        der[out_len] = p[i];
        out_len++;
    }
    *der_len = out_len;
}

static
void extract_certificates_from_response_header
(
    CURL* curl,
    const char* header,
    size_t header_len,
    attestation_verification_report_t* attn_report
)
{
    // Locate x-iasreport-signature HTTP header field in the response.
    const char response_header_name[] = "x-iasreport-signing-certificate: ";
    char *field_begin = memmem(header,
                               header_len,
                               response_header_name,
                               strlen(response_header_name));
    assert(field_begin != NULL);
    field_begin += strlen(response_header_name);
    const char http_line_break[] = "\r\n";
    char *field_end = memmem(field_begin,
                             header_len - (field_begin - header),
                             http_line_break,
                             strlen(http_line_break));
    size_t field_len = field_end - field_begin;

    // Remove urlencoding from x-iasreport-signing-certificate field.
    int unescaped_len = 0;
    char* unescaped = curl_easy_unescape(curl,
                                         field_begin,
                                         field_len,
                                         &unescaped_len);
    
    char* cert_begin = memmem(unescaped,
                              unescaped_len,
                              pem_marker_begin,
                              strlen(pem_marker_begin));
    assert(cert_begin != NULL);
    char* cert_end = memmem(unescaped, unescaped_len,
                            pem_marker_end, strlen(pem_marker_end));
    assert(cert_end != NULL);
    uint32_t cert_len = cert_end - cert_begin + strlen(pem_marker_end);

    /* This is an overapproximation: after converting from PEM to
       base64-encoded DER the actual size will be less than
       cert_len. */
    assert(cert_len <= sizeof(attn_report->ias_sign_cert));
    pem_to_base64_der(cert_begin, cert_len,
                      (char*) attn_report->ias_sign_cert,
                      &attn_report->ias_sign_cert_len,
                      sizeof(attn_report->ias_sign_cert));
    
    cert_begin = memmem(cert_end,
                        unescaped_len - (cert_end - unescaped),
                        pem_marker_begin,
                        strlen(pem_marker_begin));
    assert(cert_begin != NULL);
    cert_end = memmem(cert_begin,
                     unescaped_len - (cert_begin - unescaped),
                     pem_marker_end,
                     strlen(pem_marker_end));
    assert(cert_end != NULL);
    cert_len = cert_end - cert_begin + strlen(pem_marker_end);

    assert(cert_len <= sizeof(attn_report->ias_sign_ca_cert));
    pem_to_base64_der(cert_begin, cert_len,
                      (char*) attn_report->ias_sign_ca_cert,
                      &attn_report->ias_sign_ca_cert_len,
                      sizeof(attn_report->ias_sign_ca_cert));

    curl_free(unescaped);
    unescaped = NULL;
}

/* The header has the certificates and report signature. */
void parse_response_header
(
    const char* header,
    size_t header_len,
    unsigned char* signature,
    const size_t signature_max_size,
    uint32_t* signature_size
)
{
    const char sig_tag[] = "x-iasreport-signature: ";
    char* sig_begin = memmem((const char*) header,
                             header_len,
                             sig_tag,
                             strlen(sig_tag));
    assert(sig_begin != NULL);
    sig_begin += strlen(sig_tag);
    char* sig_end = memmem(sig_begin,
                           header_len - (sig_begin - header),
                           "\r\n",
                           strlen("\r\n"));
    assert(sig_end);

    assert((size_t) (sig_end - sig_begin) <= signature_max_size);
    memcpy(signature, sig_begin, sig_end - sig_begin);
    *signature_size = sig_end - sig_begin;
}

/** Turns a binary quote into an attestation verification report.

  Communicates with Intel Attestation Service via its HTTP REST interface.
*/
void obtain_attestation_verification_report
(
    const sgx_quote_t* quote,
    const uint32_t quote_size,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
 )
{
    CURL *curl;
    CURLcode res;
    int ret;
  
    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        char url[512];
        ret = snprintf(url, sizeof(url), "https://%s/attestation/sgx/v2/report",
                           opts->ias_server);
        assert(ret < (int) sizeof(url));
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLCERT, opts->ias_cert_file);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, opts->ias_key_file);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        const char json_template[] = "{\"isvEnclaveQuote\":\"%s\"}";
        unsigned char quote_base64[quote_size * 2];
        char json[quote_size * 2];

        ret = EVP_EncodeBlock(quote_base64, (unsigned char*) quote, quote_size);
         // +1 since EVP_EncodeBlock() adds \0 to the output.
        assert((size_t) ret + 1 <= sizeof(quote_base64));

        snprintf(json, sizeof(json), json_template, quote_base64);
    
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);

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
        
        /* printf("%s", header.data); */
        /* printf("body= %s", body.data); */

        parse_response_header(header.data, header.len,
                              attn_report->ias_report_signature,
                              sizeof(attn_report->ias_report_signature),
                              &attn_report->ias_report_signature_len);

        const int body_base64_size = (body.len % 3 == 0) ?
            body.len / 3 * 4 :
            body.len + (3 - body.len % 3) / 3 * 4;
    
         // +1 since EVP_EncodeBlock() puts a \0 at the end ...
        assert(sizeof(attn_report->ias_report) >= (size_t) body_base64_size + 1);
        ret = EVP_EncodeBlock(attn_report->ias_report,
                              (unsigned char*) body.data, body.len);
        assert(ret == body_base64_size);
         // Here we ignore the trailing \0
        attn_report->ias_report_len = body_base64_size;

        extract_certificates_from_response_header(curl,
                                                  header.data, header.len,
                                                  attn_report);
    
        /* Check for errors */
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);

        free(header.data);
        free(body.data);
    }

    curl_global_cleanup();
}
