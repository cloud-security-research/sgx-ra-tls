// Copied from Graphene-SGX.

#define EREPORT     0
  
/*
 * sgx_report:
 * Generate SGX hardware signed report.
 */
	.global sgx_report
	.type sgx_report, @function

sgx_report:
	.cfi_startproc

	push %rbx
	push %rcx
	mov %rdi, %rbx
	mov %rsi, %rcx
	mov $EREPORT, %rax
	ENCLU
	pop %rcx
	pop %rbx
	ret

	.cfi_endproc
	.size sgx_report, .-sgx_report
