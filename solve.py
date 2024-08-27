from pwn import *

elf = './babyrev_level19.0'




def enter_key(p, key):
    recvd = p.recvuntil('read_memory')
    p.sendline(key)
    return recvd

if __name__ == '__main__':
    p = process(elf)
    print(enter_key(p, 'HELLO').decode())
    p.interactive()
