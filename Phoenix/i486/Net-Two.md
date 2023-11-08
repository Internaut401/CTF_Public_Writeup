# NET TWO


## SOURCE CODE
```c
/*
 * phoenix/net-two, by https://exploit.education
 *
 * Shout out to anyone who doesn't know what the opposite of in is.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  int i;
  unsigned long quad[sizeof(long)], result, wanted;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("%s\nFor this level, sizeof(long) == %d, keep that in mind :)\n",
      BANNER, (int)sizeof(long));

  if (getrandom((void *)&quad, sizeof(quad), 0) != sizeof(quad)) {
    errx(1, "unable to getrandom(%d bytes)", sizeof(quad));
  }

  result = 0;
  for (i = 0; i < sizeof(long); i++) {
    result += quad[i];
    if (write(1, (void *)&quad[i], sizeof(long)) != sizeof(long)) {
      errx(1, "Why have you foresaken me, write()");
    }
  }

  if (read(0, (void *)&wanted, sizeof(long)) != sizeof(long)) {
    errx(1, "Unable to read\n");
  }

  if (result == wanted) {
    printf("You have successfully passed this level, well done!\n");
  } else {
    printf("Whoops, better luck next time. Receieved %lu, wanted %lu\n", wanted,
        result);
  }

  return 0;
}
```


## STRATEGY
The code, generate and send us 4 random numbers (long int - 4 byte each). Then it compares our input to the sum of these four numbers. Since i solved in python we need to take care about the overflow ! So i add an AND mask (0xffffffff) to clean overflow

## EXPLOIT
```python
import socket
import struct

HOST = '127.0.0.1'
PORT = 64012

def read_line (socket):
     buf = ""
     while True:
         c = s.recv(1)
         if c == b'\n':
            break
         buf += c.decode("ascii")
     return buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
print(read_line(s))
print(read_line(s))
num = s.recv(4)
num += s.recv(4)
num += s.recv(4)
num += s.recv(4)
N = struct.unpack("IIII", num)
print N
print "Without overflow: "
print N
sN = sum(N)
print sN
sN &= 0xffffffff
s.send(struct.pack("I", sN))
print (read_line(s))

s.close()
quit()
```
