from pwn import *
p = process ("./chall_17")
context.arch = "amd64" 
elf = ELF("./chall_17") 

from ctypes import *
libc = cdll.LoadLibrary('libc.so.6')
libc.srand(libc.time(None))

p.sendline(str(libc.rand()))
log.info('flag: ' + p.recvline().decode("iso-8859-1"))
