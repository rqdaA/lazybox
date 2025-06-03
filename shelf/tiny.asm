global _start
section .text
_start:
  mov rax, 59
  mov rdi, 0x68732f6e69622f
  push rdi
  mov rdi, rsp
  xor esi, esi
  xor edx, edx
  syscall
