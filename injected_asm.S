.global _start
.text
_start:
	pushq %rax
	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	leaq 2(%rip), %rsi
	jmp _callputs
	.byte 0x49, 0x00
_callputs:
	movq $1, %rax
	movq $1, %rdi
	movq $2, %rdx
	syscall
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
	popq %rax
