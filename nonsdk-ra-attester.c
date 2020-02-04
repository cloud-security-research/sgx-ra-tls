/* This code generates a quote without using the SGX SDK. We
   communicate directly with the architecture enclave (AE) over
   protocol buffers. */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <sgx_report.h>

#include "ra.h"
#include "ra-attester.h"
#include "ias-ra.h"

void do_remote_attestation(sgx_report_data_t* report_data, const struct ra_tls_options* opts,
                           attestation_verification_report_t* attn_report)
{
    (void) opts;

    int fd = open("/sys/sgx_attestation/report_data", O_WRONLY);
    if (fd < 0)
        abort();
    int rc = write(fd, report_data, sizeof(*report_data));
    if (rc != sizeof(*report_data))
        abort();
    close(fd);

    obtain_attestation_verification_report(NULL, 0, NULL, attn_report);
}

void ra_tls_create_report(sgx_report_t* report)
{
    int fd = open("/sys/sgx_attestation/report", O_RDONLY);
    if (fd < 0)
        abort();
    int rc = read(fd, report, sizeof(*report));
    if (rc != sizeof(*report))
        abort();
    close(fd);
}
