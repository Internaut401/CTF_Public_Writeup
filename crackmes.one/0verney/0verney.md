# 0verney

### Link to the challenge
[https://crackmes.one/crackme/6049f27f33c5d42c3d016dea](https://crackmes.one/crackme/6049f27f33c5d42c3d016dea)

### Anti-debug bypass
The first thing we can notice is the presence of an anti-debug mechanism.
We can run the program normally, but if we run it from gdb it exits ...

```shell
[marco@marco-xps139343 Desktop]$ ./0verney
Hello there!
AAAAA
Bad!
```
```shell
pwndbg> r
Starting program: /home/marco/Desktop/0verney 
[Inferior 1 (process 19255) exited normally]
```
Trying to trace the execution with the `strace` tool you can see how the program executes a "ptrace" syscall.
Ptrace can only be executed by a program that is not itself a "tracee", ie it is not being traced.
See ptrace linux man page for more details.
```shell
[marco@marco-xps139343 Desktop]$ strace ./0verney
execve("./0verney", ["./0verney"], 0x7ffdee75bfc0 /* 70 vars */) = 0
...
some stuff
...
ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)
exit(0)                                 = ?
+++ exited with 0 +++
```

At this point we have to find the point where the syscall to ptrace is performed and we have two choices:
- skip the instruction every time we debug the program with gdb (bad choice if you have to do the dynamic analysis many times)
- patch the program (bad choice if the patched instruction changes the behavior of the program)

We then look for where it is used and then decide.
```asm
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_0c003f7e()
             undefined         AL:1           <RETURN>
                             FUN_0c003f7e                                    XREF[2]:     __libc_csu_init:00401199(c), 
                                                                                          00403e00(*)  
        0c003f7e 55              PUSH       RBP
        0c003f7f 48 89 e5        MOV        RBP,RSP
        0c003f82 eb 02           JMP        LAB_0c003f86
        0c003f84 0d              ??         0Dh
        0c003f85 52              ??         52h    R
                             LAB_0c003f86                                    XREF[1]:     0c003f82(j)  
        0c003f86 b8 65 00        MOV        EAX,0x65
                 00 00
        0c003f8b 48 31 ff        XOR        RDI,RDI
        0c003f8e 48 31 f6        XOR        RSI,RSI
        0c003f91 4d 31 d2        XOR        R10,R10
        0c003f94 48 31 d2        XOR        RDX,RDX
        0c003f97 48 ff c2        INC        RDX
        0c003f9a eb 02           JMP        LAB_0c003f9e
        0c003f9c f5              ??         F5h
        0c003f9d a9              ??         A9h
                             LAB_0c003f9e                                    XREF[1]:     0c003f9a(j)  
        0c003f9e 0f 05           SYSCALL
        0c003fa0 eb 02           JMP        LAB_0c003fa4
        0c003fa2 cd              ??         CDh
        0c003fa3 52              ??         52h    R
                             LAB_0c003fa4                                    XREF[1]:     0c003fa0(j)  
        0c003fa4 48 83 f8 00     CMP        RAX,0x0
        0c003fa8 7d 0a           JGE        LAB_0c003fb4
        0c003faa b8 3c 00        MOV        EAX,0x3c
                 00 00
        0c003faf 48 31 ff        XOR        RDI,RDI
        0c003fb2 0f 05           SYSCALL
                             LAB_0c003fb4                                    XREF[1]:     0c003fa8(j)  
        0c003fb4 5d              POP        RBP
        0c003fb5 c3              RET
```

The function is called by `__libc_csu_init`, which means it is a constructor and will therefore be executed before the main.
The function has no purpose in the program other than to interrupt its execution in case it is being debugged by a debugger. I decided to patch the instruction changing the syscall number from 0x65 (ptrace) to -> 0x66 (getuid). This is because getuid takes no parameters and does nothing in particular except ask the kernel for the user id.
syscall table: https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md <br>
To patch the instruction i used ghidra, and to apply the patch i've used a python ghidra plugin:
https://github.com/schlafwandler/ghidra_SavePatch

Analyzing the program, we can notice that one of the dtors actually map some rwx page in memory, then unpack some bytes geenrating a shellcode. One solution could be copy, the unpacker function and extract the shellcode. I choose to analyze the unpacked shellcode through dynamic analysis, so i basically break with GDB once the the shellcode interact with the user asking for a input. 
With dynamic analysis we can see that the program cycles through all bytes of our input until it encounters a "newline" character. At each cycle it adds the value of the byte in the rbx register which keeps the total sum:
```asm
   0x7ffff7ffa0d9    mov    al, byte ptr [rsp + rcx]
   0x7ffff7ffa0dc    cmp    al, 0xa
 ► 0x7ffff7ffa0de    je     0x7ffff7ffa0e8 <0x7ffff7ffa0e8>
 
   0x7ffff7ffa0e0    add    rbx, rax
   0x7ffff7ffa0e3    inc    rcx
   0x7ffff7ffa0e6    jmp    0x7ffff7ffa0d9 <0x7ffff7ffa0d9>
```
What the program does is:
user_input XOR 0xaf75 == 0xacab?
if the equation matches, the program will print "G00d" and we will win.
```asm
   0x7ffff7ffa0ec    mov    eax, 0xaf75
   0x7ffff7ffa0f1    xor    rax, rbx
   0x7ffff7ffa0f4    jmp    0x7ffff7ffa0f8 <0x7ffff7ffa0f8>
    ↓
   0x7ffff7ffa0f8    cmp    rax, 0xacab
   0x7ffff7ffa0fe    je     0x7ffff7ffa11b <0x7ffff7ffa11b>


pwndbg> x/10i 0x7ffff7ffa11b
   0x7ffff7ffa11b:      push   0x64303047
   0x7ffff7ffa120:      mov    eax,0x1
   0x7ffff7ffa125:      mov    edi,0x1
   0x7ffff7ffa12a:      mov    rsi,rsp
   0x7ffff7ffa12d:      mov    edx,0x6
   0x7ffff7ffa132:      syscall 
   0x7ffff7ffa134:      mov    eax,0x3c
   0x7ffff7ffa139:      xor    rdi,rdi
   0x7ffff7ffa13c:      syscall 
   0x7ffff7ffa13e:      in     eax,0x48
```
Xor is an operator with commutative property, so we can swap members in the equation:
0xacab XOR 0xaf75 = user_input = 990 (decimal).
# FLAG
Any solution is valid unti the equation is correct. 
Example `cccccccccc`
