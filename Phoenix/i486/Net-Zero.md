# NET ZERO


## SOURCE CODE

```c
/*
 * phoenix/net-zero, by https://exploit.education
 *
 * What did the fish say when he swam head first into a wall?
 * Dam!
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  uint32_t i, j;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("%s\n", BANNER);

  if (getrandom((void *)&i, sizeof(i), 0) != sizeof(i)) {
    errx(1, "unable to getrandom(%d bytes)", sizeof(i));
  }

  printf("Please send '%u' as a little endian, 32bit integer.\n", i);

  if (read(0, (void *)&j, sizeof(j)) != sizeof(j)) {
    errx(1, "unable to read %d bytes from stdin", sizeof(j));
  }

  if (i == j) {
    printf("You have successfully passed this level, well done!\n");
  } else {
    printf("Close - you sent %u instead\n", j);
  }

  return 0;
}

```


## STRATEGY

The page on exploit education tells us there is a service called Net-Zero running with loopback ip address (127.0.0.1) on 64010 port.
The program is a web-server which gives us a number. We need to send it back in little-endian integer form.

## EXPLOIT
```python
import socket
import struct

HOST = '127.0.0.1'
PORT = 64010


def read_line (socket):
    buf = ""
    while True:
        c = s.recv(1)
        if c == b'\n':
            break
        buf += c.decode("ascii")
    return buf


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print (read_line(s))
    data = read_line(s)
    print (data)
    
    n = str(data).split("'")[1]
    s.sendall(struct.pack("I", int(n)))
    print(read_line(s))
    s.close()

quit()

```
