#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <string.h>

#include "mbedtls/config.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "mbedtls-ra-attester.h"

unsigned char secret[1024];

struct ra_tls_options my_ra_tls_options = {
    .spid = {{0xAC, 0xF4, 0x77, 0x84, 0x9A, 0x55, 0x53, 0x12,
              0x5E, 0xC9, 0xC2, 0xD4, 0xA0, 0x53, 0x38, 0xDA}},
    .quote_type = SGX_UNLINKABLE_SIGNATURE,
    .ias_server = "api.trustedservices.intel.com/sgx/dev",
    .subscription_key = "ce00381c4ef747769a9bde7edadf2f99"
};

static
void ssl_read_exactly_n_bytes(mbedtls_ssl_context* ssl, unsigned char* p, int len) {
    int bytes_read = 0;
    int ret;
    do {
        ret = mbedtls_ssl_read(ssl, p + bytes_read, len - bytes_read);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        assert(ret >= 0);
        if (ret == 0) break;
        bytes_read += ret;
        if (bytes_read == len) break;
    } while (1);
    assert(bytes_read == len);
}

int grab_secret_from_provisioning_service(int argc, char **argv, char **env) {
    (void)env;

    /* Connect to verifier / secret provisioning service. */
    mbedtls_net_context srv_fd;
    const char *personalize = "redis-server-attester.so";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;

    mbedtls_x509_crt crt;
    mbedtls_pk_context key;

    mbedtls_net_init(&srv_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&srvcert);
    
    /* Generate RA-TLS certificate and key. */
    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&key);
    mbedtls_create_key_and_x509(&key, &crt, &my_ra_tls_options);

    mbedtls_entropy_init(&entropy);
    assert(0 == mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                      &entropy,
                                      (const unsigned char*) personalize,
                                      strlen(personalize)));

    
    assert(0 == mbedtls_net_connect(&srv_fd, "127.0.0.1",
                                    "12345", MBEDTLS_NET_PROTO_TCP));

    assert(0 == mbedtls_ssl_config_defaults(&conf,
                                            MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_STREAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT));
    
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    /* mbedtls_ssl_conf_dbg(&conf, my_debug, stdout); */
    assert(0 == mbedtls_x509_crt_parse_file(&srvcert, "verifier-crt.pem"));

    mbedtls_ssl_conf_ca_chain(&conf, &srvcert, NULL);
    assert(0 == mbedtls_ssl_conf_own_cert(&conf, &crt, &key));
        
    assert(0 == mbedtls_ssl_setup(&ssl, &conf));
    mbedtls_ssl_set_bio(&ssl, &srv_fd, mbedtls_net_send,
                        mbedtls_net_recv, NULL);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        assert(ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    }

    
    /* Grab secret from secret provisioning service. */
    int32_t secret_size;
    ssl_read_exactly_n_bytes(&ssl, (unsigned char*) &secret_size, sizeof(secret_size));
    assert(secret_size <= (int) sizeof(secret));
    ssl_read_exactly_n_bytes(&ssl, (unsigned char*) secret, secret_size);
    
    printf(" > Provisioning successful. Secret is: %s\n", (char*)secret);

    /* Patch --requirepass command-line argument to point to obtained secret. */
    const char* requirepass = "--requirepass";
    for (int i = 0; i < argc; i++) {
        if ((strncmp(requirepass, argv[i], strlen(requirepass)) == 0) && (i + 1 < argc)) {
            printf(" > Found `%s <dummypass>`. Overwriting as `%s %s`\n",
                   requirepass, requirepass, (char*)secret);
            argv[i + 1] = (char*) secret;
        }
    }

    return 0;
}

/* We rely on Glibc behavior that grab_secret_from_provisioning_service() is called during
 * initialization with access to exactly the same stack frame as main(). This allows to
 * intercept argc, argv, and envp, and modify argv for our secret-provisioning purpose. */
__attribute__((section(".init_array")))
void *grab_secret_from_provisioning_service_constructor = &grab_secret_from_provisioning_service;
