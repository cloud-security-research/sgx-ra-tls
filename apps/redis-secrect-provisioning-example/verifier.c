/*
 *  SSL server demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time       time
#define mbedtls_time_t     time_t 
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) ||    \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) || \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||     \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||    \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
           "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
           "and/or MBEDTLS_PEM_PARSE_C not defined.\n");
    return( 0 );
}
#else

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define DEBUG_LEVEL 0

#include <sgx_quote.h>

#include "mbedtls-ra-attester.h"
#include "ra-challenger.h"

extern const char redis_server_mrenclave[];
extern const char redis_server_mrsigner[];

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

extern struct ra_tls_options my_ra_tls_options;

/**
 * @return 0 to indicate successful verification, 1 otherwise.
 */
static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {

    if (depth != 0) return 0;

    (void) data;

    if (*flags == MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
        *flags = 0;
    }
    assert(*flags == 0);
    
    return verify_sgx_cert_extensions(crt->raw.p, crt->raw.len);
}

int main( void )
{
    int ret;
    mbedtls_net_context listen_fd, client_fd;
    const char *pers = "ssl_server";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    mbedtls_net_init( &listen_fd );
    mbedtls_net_init( &client_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_debug_set_threshold( DEBUG_LEVEL );

    /*
     * 1. Generate the certificate and private RSA key
     */
    mbedtls_printf( "\n  . Loading server cert. and key..." );
    fflush( stdout );

    ret = mbedtls_x509_crt_parse_file(&srvcert, "verifier-crt.pem");
    assert(ret == 0);
    ret = mbedtls_pk_parse_keyfile(&pkey, "verifier-key.pem", NULL);
    assert(ret == 0);

    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup the listening TCP socket
     */
    const char* ip = "127.0.0.1";
    const char* port = "12345";
    mbedtls_printf( "  . Bind on https://%s:%s/ ...", ip, port);
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, ip, port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 3. Seed the RNG
     */
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL data...." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ca_chain( &conf, &srvcert, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    /* Must set _REQUIRED to force client to send a
       certificate. Unfortunately, this also requires us to install a
       CA chain here.*/
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_verify(&conf, my_verify, NULL);
    
    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &client_fd );

    mbedtls_ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
                                    NULL, 0, NULL ) ) != 0 )
    {
        char errbuf[512];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        mbedtls_printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
        mbedtls_printf("%s\n", errbuf);
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    mbedtls_printf( " ok\n" );

    /*
     * 5. Handshake
     */
    mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        assert(ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    }

    const mbedtls_x509_crt* client_crt = mbedtls_ssl_get_peer_cert(&ssl);
    assert(client_crt != NULL);
    
    sgx_quote_t quote;
    get_quote_from_cert(client_crt->raw.p, client_crt->raw.len, &quote);
    sgx_report_body_t* body = &quote.report_body;

    /* char mrenclave_hex_str[SGX_HASH_SIZE * 2 + 1] = {0, }; */
    /* char mrsigner_hex_str[SGX_HASH_SIZE * 2 + 1] = {0, }; */
    /* for (int i = 0; i < SGX_HASH_SIZE; ++i) { */
    /*     sprintf(&mrenclave_hex_str[i*2], "%02x", body->mr_enclave.m[i]); */
    /*     sprintf(&mrsigner_hex_str[i*2], "%02x", body->mr_signer.m[i]); */
    /* } */

    if (memcmp(body->mr_enclave.m, redis_server_mrenclave, sizeof(body->mr_enclave.m)) != 0) {
        mbedtls_printf(" ... failed. Unexpected peer MRENCLAVE!\n");
        goto reset;
    }

    if (memcmp(body->mr_signer.m, redis_server_mrsigner, sizeof(body->mr_signer.m)) != 0) {
        mbedtls_printf(" ... failed. Unexpected peer MRSIGNER!\n");
        goto reset;
    }

    mbedtls_printf( " ok\n" );
    
    /*
     * 7. Write the 200 Response
     */
    mbedtls_printf( "  > Sending secret to redis server ..." );
    fflush( stdout );

    const char* secret = "intelsgxrocks!";
    const int32_t secret_len = strlen(secret) + 1;

    assert((int) sizeof(secret_len) == mbedtls_ssl_write(&ssl, (unsigned char*) &secret_len,
                                                         sizeof(secret_len)));
    assert(secret_len == mbedtls_ssl_write(&ssl, (unsigned char*) secret,
                                           secret_len));
    mbedtls_printf( " done\n" );
    fflush(stdout);

    mbedtls_printf( "  . Closing the connection..." );

    while( ( ret = mbedtls_ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret );
            goto reset;
        }
    }

    mbedtls_printf( " ok\n" );

    ret = 0;
    goto reset;

exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &client_fd );
    mbedtls_net_free( &listen_fd );

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C
          && MBEDTLS_FS_IO && MBEDTLS_PEM_PARSE_C */
