/* This code generates a quote without using the SGX SDK. We
   communicate directly with the architecture enclave (AE) over
   protocol buffers. */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <sgx_uae_service.h>
#include <sgx_report.h>

#include "ra.h"
#include "ra-attester.h"
#include "ra_private.h"
#include "ias-ra.h"
#include "messages.pb-c.h"

#include <trts_inst.h>
#include <util.h> // ROUND_TO macro
#include <se_memcpy.h>

#include <epid/common/types.h>
#include <internal/se_quote_internal.h>

/* Each protobuf is preceeded by its length stored in a uint32_t. */
static uint32_t hdr_len = sizeof(uint32_t);

/* Prepend my_ to prevent name clash with SGX SDK's declaration. Make
   the simplifying assumption of no revocation lists. */
static
sgx_status_t my_sgx_calc_quote_size(const uint8_t *sig_rl, uint32_t sig_rl_size, uint32_t* p_quote_size)
{
    assert(p_quote_size);
    assert(sig_rl == NULL);
    assert(sig_rl_size == 0);

    uint64_t quote_size = 0;
    uint64_t sign_size = 0;

    sign_size = sizeof(EpidSignature) - sizeof(NrProof);
    quote_size = SE_QUOTE_LENGTH_WITHOUT_SIG + sign_size;
    assert(quote_size < (1ull << 32));
    
    *p_quote_size = (uint32_t)(quote_size);
    return SGX_SUCCESS;
}

static
void init_quote_request(int fd) {
    Aesm__Message__Request__InitQuoteRequest req = AESM__MESSAGE__REQUEST__INIT_QUOTE_REQUEST__INIT;
    Aesm__Message__Request msg = AESM__MESSAGE__REQUEST__INIT;
    msg.initquotereq = &req;
    
    uint32_t proto_len = aesm__message__request__get_packed_size(&msg);
    uint32_t len = hdr_len + proto_len;
    
    char* buf = malloc(len);

    memcpy(buf, (uint8_t*)&proto_len, hdr_len);
    aesm__message__request__pack(&msg, (uint8_t*) (buf + hdr_len));

    int rc = send(fd, buf, len, 0);
    assert((ssize_t) rc == len);
    free(buf);
}

static
void init_quote_response
(
    int fd,
    sgx_target_info_t* target_info,
    sgx_epid_group_id_t* group_id
)
{
    // 4 byte payload size
    uint32_t reply_len;
    int rc = recv(fd, &reply_len, sizeof(reply_len), 0);
    assert(rc == sizeof(uint32_t));

    // payload
    uint8_t* reply = malloc(reply_len);
    assert(reply != NULL);
    rc = recv(fd, reply, reply_len, 0);
    assert((ssize_t) rc == reply_len);

    // de-serialize protobuf
    Aesm__Message__Response* msg =
        aesm__message__response__unpack(NULL, reply_len, reply);

    assert(msg->initquoteres != NULL);
    Aesm__Message__Response__InitQuoteResponse* qr = msg->initquoteres;
    assert(qr->has_targetinfo);
    assert(qr->has_gid);

    assert(qr->targetinfo.len == sizeof(*target_info));
    assert(qr->gid.len == sizeof(*group_id));
    memcpy(target_info, qr->targetinfo.data, sizeof(*target_info));
    memcpy(group_id, qr->gid.data, sizeof(*group_id));

    free(reply); reply = NULL;
}

int sgx_report(void*, void*, void*);

#ifdef DEBUG
static void hex_print(uint8_t* str, size_t len) {
    for (uint32_t i = 0; i < len; ++i) printf("%02x", str[i]);
    printf("\n");
}
#endif

void create_report
(
    sgx_target_info_t* target_info,
    const sgx_report_data_t* report_data,
    sgx_report_t* report
)
{
    assert(target_info != NULL);
    assert(report_data != NULL);
    assert(report != NULL);

    // We do not check if input parameters are in enclave memory. We assume we
    // run on Graphene and all memory allocated within the Graphene
    // application is enclave memory.

    /* This code is adapted from SDK's sgx_create_report() in
     * sgx_create_report.cpp */
    size_t size = ROUND_TO(sizeof(sgx_target_info_t), TARGET_INFO_ALIGN_SIZE) +
                  ROUND_TO(sizeof(sgx_report_data_t), REPORT_DATA_ALIGN_SIZE) +
                  ROUND_TO(sizeof(sgx_report_t), REPORT_ALIGN_SIZE);
    size += MAX(MAX(TARGET_INFO_ALIGN_SIZE, REPORT_DATA_ALIGN_SIZE), REPORT_ALIGN_SIZE) - 1;

    void *buffer = malloc(size);
    assert(buffer != NULL);

    memset(buffer, 0, size);
    size_t buf_ptr = (size_t) (buffer);

    buf_ptr = ROUND_TO(buf_ptr, REPORT_ALIGN_SIZE);
    sgx_report_t *tmp_report = (sgx_report_t*) (buf_ptr);
    buf_ptr += sizeof(*tmp_report);

    buf_ptr = ROUND_TO(buf_ptr, TARGET_INFO_ALIGN_SIZE);
    sgx_target_info_t *tmp_target_info = (sgx_target_info_t*) (buf_ptr);
    buf_ptr += sizeof(*tmp_target_info);

    buf_ptr = ROUND_TO(buf_ptr, REPORT_DATA_ALIGN_SIZE);
    sgx_report_data_t *tmp_report_data = (sgx_report_data_t*) (buf_ptr);

    // Copy data from user buffer to the aligned memory
    memcpy_s(tmp_target_info, sizeof(*tmp_target_info), target_info, sizeof(*target_info));
    memcpy_s(tmp_report_data, sizeof(*tmp_report_data), report_data, sizeof(*report_data));

    sgx_report(tmp_target_info, tmp_report_data, tmp_report);
    /* for (int i = 0; i < sizeof(*report); ++i) printf("%02x", ((uint8_t*) tmp_report)[i]); */

    memcpy_s(report, sizeof(*report), tmp_report, sizeof(*tmp_report));

    /* hex_print((uint8_t*) report, sizeof(*report)); */
#ifdef DEBUG
    hex_print((uint8_t*) &report->body.mr_enclave, sizeof(sgx_measurement_t));
    hex_print((uint8_t*) &report->body.mr_signer, sizeof(sgx_measurement_t));
#endif
    
    free(buffer); buffer = NULL;
}

static
void get_quote_request(
    int fd,
    sgx_report_t* report,
    sgx_quote_sign_type_t quote_type,
    sgx_spid_t* spid,
    uint32_t quote_size
    )
{
    Aesm__Message__Request__GetQuoteRequest req = AESM__MESSAGE__REQUEST__GET_QUOTE_REQUEST__INIT;
    Aesm__Message__Request msg = AESM__MESSAGE__REQUEST__INIT;
    msg.getquotereq = &req;

    req.report.data = (uint8_t*) report;
    req.report.len = sizeof(*report);
    /* printf("len report= %lu\n", sizeof(*report)); */
    req.quote_type = quote_type;
    req.spid.data = (uint8_t*) spid;
    req.spid.len = sizeof(*spid);
    /* printf("len spid= %lu\n", sizeof(*spid)); */
    req.has_qe_report = 1;
    req.qe_report = 0;
    req.has_timeout = 1;
    req.timeout = 15000;
    req.buf_size = quote_size;
    
    uint32_t payload_len = aesm__message__request__get_packed_size(&msg);
    uint32_t total_len = hdr_len + payload_len;
    
    char* buf = malloc(total_len);
    assert(buf != NULL);

    memcpy(buf, (uint8_t*)&payload_len, hdr_len);
    aesm__message__request__pack(&msg, (uint8_t*) buf + hdr_len);

    int rc = send(fd, buf, total_len, 0);
    assert((ssize_t) rc == total_len);
    free(buf);
}

static
void get_quote_response(
    int fd,
    sgx_quote_t* quote,
    uint32_t quote_size
    )
{
    // header
    uint32_t payload_len;
    int rc = recv(fd, &payload_len, sizeof(payload_len), 0);
    assert(rc == sizeof(uint32_t));

    // payload
    uint8_t* payload = malloc(payload_len);
    assert(payload != NULL);
    rc = recv(fd, payload, payload_len, 0);
    assert(rc != -1);
    assert((ssize_t) rc == payload_len);

    Aesm__Message__Response* msg =
        aesm__message__response__unpack(NULL, payload_len, payload);
    assert(msg->getquoteres != NULL);
    Aesm__Message__Response__GetQuoteResponse* r = msg->getquoteres;
    assert(r->has_quote);
    assert(r->quote.len == quote_size);
    memcpy_s(quote, quote_size, r->quote.data, r->quote.len);
}

static
int open_socket(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd != -1);

    /* We assume the aesmd is reachable on 127.0.0.1:1234 by
       default. You may have to run a socat instance on the host to
       achieve this: socat -t10
       TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8
       UNIX-CLIENT:/var/run/aesmd/aesm.socket */
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    char* ip = getenv("RATLS_AESMD_IP");
    if (ip == NULL) ip = (char*) "127.0.0.1";
    inet_pton(AF_INET, ip, &(saddr.sin_addr));
    saddr.sin_port = htons(1234);
    
    int rc = connect(fd, (const struct sockaddr*) &saddr, sizeof(saddr));
    assert(rc != -1);
    
    return fd;
}

static
sgx_quote_t* alloc_quote(uint32_t* sz) {
    my_sgx_calc_quote_size(NULL, 0, sz);
    void* b = malloc(*sz);
    return (sgx_quote_t*) b;
}

static
void free_quote(sgx_quote_t* q) {
    free(q);
}

static
void get_quote
(
    sgx_spid_t spid, // in
    sgx_quote_sign_type_t quote_type, // in
    sgx_report_data_t* report_data, // in
    sgx_quote_t* quote, // out
    uint32_t quote_size
)
{
    int fd = open_socket();
    init_quote_request(fd);

    sgx_target_info_t target_info = {0, };
    sgx_epid_group_id_t group_id = {0, };
    init_quote_response(fd, &target_info, &group_id);
    close(fd);

    // This executes the EREPORT instruction.
    sgx_report_t report = {0, };
    create_report(&target_info, report_data, &report);

    fd = open_socket();

    get_quote_request(fd, &report, quote_type, &spid, quote_size);
    get_quote_response(fd, quote, quote_size);
    close(fd);
}

void do_remote_attestation
(
    sgx_report_data_t* report_data,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    uint32_t quote_size;
    sgx_quote_t* quote = alloc_quote(&quote_size);
    assert(quote != NULL);

    get_quote(opts->spid,
              opts->quote_type,
              report_data,
              quote,
              quote_size);

    obtain_attestation_verification_report(quote,
                                           quote_size,
                                           opts,
                                           attn_report);
    free_quote(quote); quote = NULL;
}

void ra_tls_create_report(
    sgx_report_t* report
)
{
    sgx_target_info_t target_info = {0, };
    sgx_report_data_t report_data = {0, };
    memset(report, 0, sizeof(*report));

    create_report(&target_info, &report_data, report);
}
