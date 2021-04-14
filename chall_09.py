from pwn import *
p = process ("./chall_09")
context.arch = "amd64" 
elf = ELF("./chall_09") 

payload = b''
payload += xor(elf.string(elf.sym.key),b"\x30")
p.sendline(payload)

p.interactive()
ls