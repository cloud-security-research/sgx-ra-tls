#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <getopt.h>

#include "ra-challenger.h"

int verify_callback
(
    int preverify_ok,
    X509_STORE_CTX *ctx
)
{
    /* We expect OpenSSL's default verification logic to complain
       about a self-signed certificate. That's fine. */
    X509* crt = X509_STORE_CTX_get_current_cert(ctx);
    if (preverify_ok == 0) {
        int err = X509_STORE_CTX_get_error(ctx);
        assert(err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
    }
    
    int der_len = i2d_X509(crt, NULL);
    assert(der_len > 0);

    unsigned char der[der_len];
    unsigned char *p = der;
    i2d_X509(crt, &p);
    
    int rc = verify_sgx_cert_extensions(der, der_len);
    printf("Verifying SGX certificate extensions ... %s\n", rc == 0 ? "Success" : "Fail");
    return !rc;
}

static
void print_sgx_crt_info(X509* crt) {
    int der_len = i2d_X509(crt, NULL);
    assert(der_len > 0);

    unsigned char der[der_len];
    unsigned char *p = der;
    i2d_X509(crt, &p);
    
    sgx_quote_t quote;
    get_quote_from_cert(der, der_len, &quote);
    sgx_report_body_t* body = &quote.report_body;

    printf("Certificate's SGX information:\n");
    printf("  . MRENCLAVE = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) printf("%02x", body->mr_enclave.m[i]);
    printf("\n");
    
    printf("  . MRSIGNER  = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) printf("%02x", body->mr_signer.m[i]);
    printf("\n");
}

static char* host = (char*) "localhost";
static int port = 443;

static
void parse_arguments(int argc, char** argv) {
    static struct option opts[] = {
        {"port", required_argument, 0, 'p'},
        {"hostname/IP", required_argument, 0, 'h'}
    };

    while (1) {
        int c;
        int option_index = 0;

        c = getopt_long(argc, argv, "p:h:", opts, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 'p':
            port = atoi(optarg);
            break;
        case 'h':
            host = optarg;
            break;
        }
    }
}

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    int ret;
    
    parse_arguments(argc, argv);
    
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    SSL_library_init();

    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());
    assert(ctx != NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &verify_callback);

    BIO *bio = BIO_new_ssl_connect(ctx);
    assert(bio != NULL);

    SSL *ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    char hostname[255];
    ret = snprintf(hostname, sizeof(hostname), "%s:%d:https", host, port);
    assert(ret > 0);
    BIO_set_conn_hostname(bio, hostname);

    if (BIO_do_connect(bio) <= 0) {
        BIO_free_all(bio);
        printf("errored; unable to connect.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    X509* crt = SSL_get_peer_certificate(ssl);
    print_sgx_crt_info(crt);
    
    char request[1024] = {0, };
    strcpy(request, "GET / HTTP/1.1\r\n\r\n");

    fcntl(0, F_SETFL, O_NONBLOCK);
    ssize_t sz = read(0, request, sizeof(request));
    /* Do not check for errors, since there may well be no input. */
    assert(sz < (ssize_t) sizeof(request)); /* Input too large. */
    
    if (BIO_puts(bio, request) <= 0) {
        BIO_free_all(bio);
        printf("errored; unable to write.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    char tmpbuf[1024+1];

    for (;;) {
        int ssllen = BIO_read(bio, tmpbuf, 1024);
        if (ssllen == 0) {
            break;
        } else if (ssllen < 0) {
            if (!BIO_should_retry(bio)) {
                printf("errored; read failed.\n");
                ERR_print_errors_fp(stderr);
                break;
            }
        } else {
            tmpbuf[ssllen] = 0;
            printf("%s", tmpbuf);
        }
    }

    BIO_free_all(bio);

    return 0;
}
