from pwn import *
p = process ("./chall_16")
context.arch = "amd64" 
elf = ELF("./chall_16") 

payload = b''
payload += (elf.string(elf.sym.key))
p.sendline(payload)

p.interactive()
ls