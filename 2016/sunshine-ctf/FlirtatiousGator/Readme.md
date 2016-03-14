```
Judges: kablaa

jump on that gator. below file running at

nc 4.31.182.242 9003

flag is in "/home/arr/flag"
```

At first the program asks for our name and reads it using `scanf("%9s",&name);`

After that it creates an array with 10 integers, sets them to 0 and asks for index and value 10 times and finally prints the values of these 10 array elements. If we enter an index bigger than or equal to 10 it exits with `exit(0)`. However it does not check wether we gave negative index or not. So for example if we give -1 index and -10 value, we can make the counter -10 and enter 20 values instead of 10. And also if we enter `-2147483648 + x` as index that would be smaller than 10 but it would access `arr[x]` due to integer overflow. So by using that we can change anywhere we want in the stack.

However, since we don't know the address of the stack, we cannot write a shellcode and return to it. But we can see from IDA that this executable has link to `system` function. We can use that to execute `/bin/sh`. For that we need a pointer to `/bin/sh`, so we need to put it to somewhere that we know we can reach. We can do it by giving address of .data to `scanf("%9s")`.

Address of .data is `0x08049b24` (we can find it using `readelf -S arr`)
Address of "%9s" is `0x0804882f` (we can find it using IDA or any other disassembler)
Address of scanf is `0x08048460` (also we can find it using any disassembler)
Address of system is `0x08048430` (also we can find it using any disassembler)

We will change the return address to scanf and give its parameters using stack. After that we need to call system, so we need a pop,pop,ret in order to pass the arguments of scanf. We can find it using `ROPgadget --binary arr`.

Address of pop,pop,ret is `0x080487ba`

So now we can form our stack:

```
| scanf address(0x08048460)  | ret address(0x080487ba)(pop pop ret)  | address of %9s(0x0804882f) | write address(0x08049b24)(.data) |
| system address(0x08048430) | anything(return address after system) | 0x08049b24(.data)          |
```

Offset of first return is 13(arr[13]).

Solution script is [here.](solution.py)