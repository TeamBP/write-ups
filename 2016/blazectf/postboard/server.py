
from cPickle import dumps
from cPickle import loads
from flask import *
from os import chroot
import random
import string
from encodings import ascii
import encodings
app = Flask(__name__)
class user_entry(object):
    def __init__(self, username, password):    
        self.u = username
        self.p = password
        self.t = gentoken()
        return None
class post_entry(object):
    def __init__(self, content, postID):    
        self.c = content
        self.i = postID
        return None
users = {}
posts = {}
with open('../flagdir/flag', 'r') as f:
    p = post_entry('flag', f.read())
    posts['flag'] = p
def gentoken():
    return ''.join(random.sample((string.ascii_lowercase * 16), 16))
def userExists(username):
    if (username in users):    
        return True
    
    return False
    return None
def addUser(username, password):
    if userExists(username):    
        return False
    
    u = user_entry(username, password)
    users[username] = u
    return True
    return None
def checkUser(username, password):
    if ((not userExists(username)) or (getUser(username).p != password)):    
        return False
    
    return True
    return None
def getUser(username):
    return users[username]
def verifySession():
    if ('auth' not in session):    
        return False
    
    u = loads(session['auth'])
    if ((not u) or (u.u not in users)):    
        session.clear()
        return False
    
    return (getUser(u.u).t == u.t)
def getPost(postID):
    if (postID not in posts):    
        return 'post not found'
    
    return posts[postID].c
    return None
def getAllPosts():
    s = "<a href='/post'>make new post</a><br><br>"
    s += '\n'.join([('<a href="/post/%s">%s</a>' % (x, x)) for x in posts])
    return s
def addPost(content, postID):
    if (postID in posts):    
        return 'Post already exists!\n'
    
    p = post_entry(content, postID)
    posts[postID] = p
    return app.make_response(redirect('/post/all'))
@app.route('/login', methods=['POST', 'GET'])
def login():
    if (request.method == 'POST'):    
        print request.form
        usern = request.form['username']
        passw = request.form['password']
        if checkUser(usern, passw):        
            redirect_to = redirect('/post/all')
            response = app.make_response(redirect_to)
            session['auth'] = dumps(getUser(usern))
            return response
        
        return 'login fail'
    else:    
        return send_from_directory('.', 'login.html')
    
    return None
@app.route('/register', methods=['POST', 'GET'])
def register():
    if (request.method == 'POST'):    
        if addUser(request.form['username'], request.form['password']):        
            return 'register success\n'
        
        return 'User Exists\n'
    else:    
        return send_from_directory('.', 'register.html')
    
    return None
@app.route('/post/<postID>', methods=['GET'])
def post_request(postID):
    if (not verifySession()):    
        return redirect(url_for('index'))
    
    if (request.method == 'GET'):    
        return get_post(postID)
    
    return 'what? be nice\n'
    return None
@app.route('/post', methods=['POST', 'GET'])
def new_post():
    if (not verifySession()):    
        return 'not authorized!\n'
    
    if (request.method == 'POST'):    
        return addPost(request.form['content'], request.form['id'])
    
    return send_from_directory('.', 'newpost.html')
    return None
def get_post(postID):
    if (postID == 'all'):    
        return getAllPosts()
    
    if (postID == 'flag'):    
        return 'This post has been disabled by the admin for being too dank\n'
    
    return getPost(postID)
    return None
@app.route('/<arg>', methods=['POST', 'GET'])
def index(arg):
    if (arg == ''):    
        arg = 'index.html'
    
    if (not verifySession()):    
        print 'send file'arg
        return send_from_directory('.', arg)
    
    return app.make_response(redirect('/post/all'))
    return None
@app.route('/', methods=['GET'])
def index_2():
    return index('')
app.secret_key = 'can_y0u_5Teal_mY+seCr3t-key'
app.run(port=1337, debug=False, host='0.0.0.0')
chroot('.')
