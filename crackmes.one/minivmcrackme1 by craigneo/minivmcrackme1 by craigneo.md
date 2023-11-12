# Complete writeup

https://negromarco.it/post/reverse-your-first-vm-obfuscated-code/

# Python solver
```python
OPcode = bytes.fromhex('39b0cb00000000ca000000004240ff000000d800000000202600000063303be9b0100c000000c89a02000003d800000000203c000000321042000000ca180000003243')
reg_init = 'vm_reg1  = 0x00000000\nvm_reg2  = 0x00000000\nvm_reg3  = 0x00000000\nvm_reg4  = 0x00000000\nvm_reg5  = 0x004016BC\nvm_reg6  = 0x004016BC\nvm_reg7  = 0x00000000\nvm_reg8  = 0x00403049\nvm_flags = 0x00000000'

def main():
    print('Register initial value:\n{0}\n\n'.format(reg_init))
    print('CODE:')
    i = 0
    while i < len(OPcode):
        match OPcode[i]:
            case 0x39:
                print('+{0:x}:\t{1}\n\t{2}'.format(i, "mov vm_reg2, [vm_reg7 + vm_reg8]", "add vm_reg7, 0x4"))
            case 0xb0:
                print('+{0:x}:\t{1}'.format(i, "mov vm_reg1, vm_reg2"))
            case 0xcb:
                print('+{0:x}:\t{1}{2}'.format(i, "mov vm_reg4, ", hex(int.from_bytes(OPcode[i+1:i+5]))))
                i += 4
            case 0xca:
                print('+{0:x}:\t{1}{2}'.format(i, "mov vm_reg3, ", hex(int.from_bytes(OPcode[i+1:i+5]))))
                i += 4
            case 0x42:
                print('+{0:x}:\t{1}'.format(i, "mov vm_reg1, [vm_reg1]"))
            case 0x40:
                print('+{0:x}:\t{1}{2}'.format(i, "and vm_reg1, ", hex(int.from_bytes(OPcode[i+1:i+5]))))
                i += 4
            case 0xd8:
                print('+{0:x}:\t{1}{2}'.format(i, "cmp vm_reg1, ", hex(int.from_bytes(OPcode[i+1:i+5]))))
                i += 4
            case 0x20:
                print('+{0:x}:\t{1}{2}'.format(i, "je vm_reg6 + ", hex(int.from_bytes(OPcode[i+1:i+5]))))
                i += 4
            case 0x63:
                print('+{0:x}:\t{1}'.format(i, "add vm_reg1, vm_reg4"))
            case 0x30:
                print('+{0:x}:\t{1}\n\t{2}'.format(i, "mov [vm_reg7 + vm_reg8 - 4], vm_reg1", "sub vm_reg7, 4"))
            case 0x3b:
                print('+{0:x}:\t{1}\n\t{2}'.format(i, "mov vm_reg4, [vm_reg7 + vm_reg8]", "add vm_reg7, 4"))
            case 0xe9:
                print('+{0:x}:\t{1}'.format(i, "inc vm_reg2"))
            case 0x10:
                print('+{0:x}:\t{1}{2}'.format(i, "jmp vm_reg6 + ", hex(int.from_bytes(OPcode[i+1:i+5]))))
                i += 4
            case 0xc8:
                print('+{0:x}:\t{1}{2}'.format(i, "mov vm_reg1, ", hex(int.from_bytes(OPcode[i+1:i+5]))))
                i += 4
            case 0x03:
                print('+{0:x}:\t{1}'.format(i, "xor vm_reg1, vm_reg4"))
            case 0x32:
                print('+{0:x}:\t{1}\n\t{2}'.format(i, "mov [vm_reg7 + vm_reg8 - 4], vm_reg3", "sub vm_reg7, 4"))
            case 0x43:
                print('+{0:x}:\t{1}'.format(i, "ret"))
            case default:
                print('+{0:x}:\t{1}'.format(i, b'UNKNOWN'))
        i += 1
    

if __name__ == "__main__":
    main()
```

Output:
```
Register initial value:
vm_reg1  = 0x00000000
vm_reg2  = 0x00000000
vm_reg3  = 0x00000000
vm_reg4  = 0x00000000
vm_reg5  = 0x004016BC
vm_reg6  = 0x004016BC
vm_reg7  = 0x00000000
vm_reg8  = 0x00403049
vm_flags = 0x00000000


CODE:
+0:     mov vm_reg2, [vm_reg7 + vm_reg8]    
        add vm_reg7, 0x4
+1:     mov vm_reg1, vm_reg2
+2:     mov vm_reg4, 0x0
+7:     mov vm_reg3, 0x0
+c:     mov vm_reg1, [vm_reg1]
+d:     and vm_reg1, 0xff000000
+12:    cmp vm_reg1, 0x0
+17:    je vm_reg6 + 0x26000000
+1c:    add vm_reg1, vm_reg4
+1d:    mov [vm_reg7 + vm_reg8 - 4], vm_reg1
        sub vm_reg7, 4
+1e:    mov vm_reg4, [vm_reg7 + vm_reg8]    
        add vm_reg7, 4
+1f:    inc vm_reg2
+20:    mov vm_reg1, vm_reg2
+21:    jmp vm_reg6 + 0xc000000
+26:    mov vm_reg1, 0x9a020000
+2b:    xor vm_reg1, vm_reg4
+2c:    cmp vm_reg1, 0x0
+31:    je vm_reg6 + 0x3c000000
+36:    mov [vm_reg7 + vm_reg8 - 4], vm_reg3
        sub vm_reg7, 4
+37:    jmp vm_reg6 + 0x42000000
+3c:    mov vm_reg3, 0x18000000
+41:    mov [vm_reg7 + vm_reg8 - 4], vm_reg3
        sub vm_reg7, 4
+42:    ret
```

The code cycles through the user input. Specifically, every character entered up to the string terminator ‘\x00’ is taken. The characters are added up. Then an xor is performed with the value 0x9a020000 (ie with 0x029a). If the result is equal to zero (therefore the sum of the characters is equal to 0x029a), the value 0x18 is put in vm_reg3, 0 otherwise. The result is then saved at the address 0x403049. Its value will be used as an offset to be added to calculate the address of the function to be invoked. If it is equal to 0, the function 0x40180b will be called (‘Bad Boy!'), otherwise it will be called 0x0040183a (‘Good Boy!').

Any input whose sum is 0x29a (666) will work, such as ‘JJJJJJJJJ’