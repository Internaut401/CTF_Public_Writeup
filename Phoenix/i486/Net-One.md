# NET ONE


## SOURCE CODE

```c
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
  uint32_t i;
  char buf[12], fub[12], *q;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("%s\n", BANNER);

  if (getrandom((void *)&i, sizeof(i), 0) != sizeof(i)) {
    errx(1, "unable to getrandom(%d bytes)", sizeof(i));
  }

  if (write(1, &i, sizeof(i)) != sizeof(i)) {
    errx(1, "unable to write %d bytes", sizeof(i));
  }

  if (fgets(buf, sizeof(buf), stdin) == NULL) {
    errx(1, "who knew that reading from stdin could be so difficult");
  }
  buf[sizeof(buf) - 1] = 0;

  q = strchr(buf, '\r');
  if (q) *q = 0;
  q = strchr(buf, '\n');
  if (q) *q = 0;

  sprintf(fub, "%u", i);
  if (strcmp(fub, buf) == 0) {
    printf("Congratulations, you've passed this level!\n");
  } else {
    printf("Close, you sent \"%s\", and we wanted \"%s\"\n", buf, fub);
  }

  return 0;
}
```


## STRATEGY
The challenge is pretty similar to 'Net-Zero'. This time we use ```recv(4)``` to read 4 bytes because the server gives us a 32-bit integer (uint32_t i), in an ASCII form. The integer is stored in *`fbuf`*, and our response is stored in *`buf`*. Those two (ASCII) buffers are then compared as strings using strcmp.


## EXPLOIT
```python
import socket
import struct

HOST = '127.0.0.1'
PORT = 64011


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
    data = s.recv(4)
    n = struct.unpack("I", data)
    s.send((str(n).split("(")[1].split(",")[0]+"\n").encode("ascii"))
    print (read_line(s))


s.close()
quit()
```
