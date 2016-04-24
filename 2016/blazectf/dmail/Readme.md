```
dmail
420

dmail is dealermail, its super secret email for only the top dealers

Host is ubuntu 14.04

107.170.17.158 4201
```

This challenge has both PIE and ASLR enabled. The program has 3 options. We can write mail, read mail and delete mail. At first mallocs a 256bytes for putting the addresses of the mails. After that when we write mail it asks for cubby id and puts the address of the mail to `addr_of_cubbies + 8 * id`. However it does not checks for the id to be less than 32. Also it has a integer stored at `0x202018`, it checks whether `(i >> (id & 0xFF) & 1` is 1 or 0. For mail it asks for the size and makes a malloc with this size and using fgets fills this memory. This part has no overflow. After getting the mail it xors `1 << (id & 0xFF)` with the integer at `0x202018`.

If we give mail size larger than 256, it does not get the mail and does not do malloc but it xors the integer.

For reading the mail the program gets the pointer from `addr_of_cubbies + 8 * id` and prints it using puts. It also checks the integer at `0x202018` for checking wether we gave any mail to that cubby or not.

For deleting teh mail it also checks with the integer at `0x202018` and deletes it using `free`. After that it xors `1 << (id & 0xFF)` with the integer at `0x202018`.

Since we know how the program works and since we know the flaw, we can start writing the attack script. The stack and heap is not executable so we need to use ROP. Since PIE and ASLR is enabled we need to find the addresses of the stack and base pointer of the glibc.

___

At first we can easily find the location of the heap. We get a mail to cubby 0 with size 256.

```
| size                |
| mail pointer 0      | <== ptrHeap
| mail pointer 1      |
| ...                 |
| mail pointer 31     |
| prev_size           |
| size                |
| start of mail1      | <== id 34
| ...                 |
| end of mail1        |
| prev_size           |
| size                |
| start of mail2      |
```

So start of the first mail is at offset 34. We get another mail to cubby 34 with size 16. Now the address of mail2 is written in mail1. So if we read the mail with id 0, we get the address of `ptrHeap + 8 * 68`.

Now if we free the first chunk, we get back_pointer and forward_pointer that point to the heap area of glibc. We do this by first writing a mail with size 16, content `ptrHeap` and another mail with size 16 content `ptrHeap`.

```
| size                |
| mail pointer 0      | <== ptrHeap
| mail pointer 1      |
| ...                 |
| mail pointer 31     |
| prev_size           |
| size                |
| start of mail1      | <== id 34
| ...                 |
| end of mail1        |
| prev_size           |
| size                |
| start of mail2      |
| end of mail2        |
| prev_size           |
| size                |
| start of mail3      | <= id 72 content ptrHeap
| end of mail3        |
| prev_size           |
| size                |
| start of mail4      | <= id 76 content ptrHeap
| end of mail4        |
```

Now we should free id 72 and read id 76. Now we have a pointer to heap of glibc. Since the offsets are the same we can calculate the offset between this pointer and main by inspectiong it from debugger. The offset is `0x22c722`. So now we have the address of main function.

By using the same technique we can find the address of glibc. If we call the pointer we found `ptr` the address of glibc is `*(ptr - 0x790) - 0x1f406`. The code section has `0x1f4a0` offset.

Now the we need to find the address of stack. The stack can be found at `*(*(ptr - 0xe8) + 0x1200)`. Lets call it ptrStack.

`writeMail` function(0xD99) has `leave` command at the end. This command replaces ebp and esp and after that pops ebp from stack. So if we change ebp before it we can control esp so we can control the return address. The function with fgets(0xCBF) has `pop rbp` at the end and we know the stack address. The address of this rbp is `ptrStack - 0x27 * 8`. So if we write a mail with `id = (ptrStack - 0x27 * 8 - ptrHeap) / 8` we make the rbp show the mail we send. It pops rbp from there and after that it gets the return addresses from there.

I asked about the glibc version of the server and the admin said the md5 of the glibc `252a9cb1b33b0d1d89a7ce8744e1cb17`. We can create the ROP using `http://ropshell.com/static/txt/252a9cb1b33b0d1d89a7ce8744e1cb17.txt.gz` this website. After sending the mail with `id = (ptrStack - 0x27 * 8 - ptrHeap) / 8`, size = 256 and content with ROP with 8 byte padding we successfully get remote shell.

The flag is `blaze{Congratulations, you've unlocked your first BlazeCTF recipe, DANK GARLICBREAD, the recipes button above the scoreboard should now be unlocked}`.
Solution script is [here.](dmail.py)

PS: Sometimes this solution may not work. One of the reasons is that if the `id = (ptrStack - 0x27 * 8 - ptrHeap) / 8` is the same with the ones we used before it'll say that this cubby is already full. Another reason is that sometimes one of the pointers will have \x00 in it. So we may not be able to get full address. Last possible reason is the last payload may have \x0a in it so the payload will get cutted from the middle. For example `pop rdi ; ret` has \x0a in it so I used `pop rdi ; pop rbp; ret`. However it should work most of the time.