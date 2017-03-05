import os
import re
import random
import hashlib
import hmac

from string import letters
from operator import is_not
from functools import partial

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = open("secret.txt",'r').read()

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class WebHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    online = db.BooleanProperty()
    email = db.StringProperty()

    def render(self):
        return render_str("friend.html", f = self)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            u.online = True
            u.put()
            return u

    @classmethod
    def logout(cls, u):
        if u:
            u.online = False
            u.put()

class Friends(db.Model):
    from_user = db.ReferenceProperty(User, collection_name = "from_user")
    to_user = db.ReferenceProperty(User, collection_name = "to_user")
    status = db.BooleanProperty()

    def render(self):
        return render_str("friend.html", f = self)

    @classmethod
    def relation(cls, user):
        relation = {}
        for to in user.from_user:
            relation[to.to_user] = to.status
        for frm in user.to_user:
            relation[frm.from_user] = frm.status
        return relation
    
    @classmethod
    def friends(cls, user):
        relation = Friends.relation(user)
        friends = {k: v for k, v in relation.iteritems() if v is True}.keys()
        return friends

    @classmethod
    def pending(cls, user):
        relation = Friends.relation(user)
        pending = {k: v for k, v in relation.iteritems() if v is False}.keys()
        return pending

    @classmethod
    def online(cls, user):
        # related_users = Friends.relation(user).keys()
        # online = list(users for users in related_users if users.online is True)
        online = list(users for users in Friends.friends(user) if users.online is True)
        return online

    @classmethod
    def offline(cls, user):
        # related_users = Friends.relation(user).keys()
        # offline = list(users for users in related_users if users.online is False)
        offline = list(users for users in Friends.friends(user) if users.online is False)
        return offline

    @classmethod
    # Returns all Friends() Class Objects where the user given, is set as the to_user; i.e for whom the invitation is sent
    def recieved(cls, user):
        pending_users = Friends.pending(user)
        recieved = [recieve.from_user.filter("to_user =", user).get() for recieve in pending_users]
        return filter(partial(is_not, None), recieved) # Removes Null for when no object was retrieved

    @classmethod
    # Returns all Friends() Class Objects where the user given, is set as the from_user; i.e who sent the invitation
    def sent(cls, user):
        pending_users = Friends.pending(user)
        sent = [send.to_user.filter("from_user =", user).get() for send in pending_users]
        return filter(partial(is_not, None), sent) # Removes Null for when no object was retrieved
    
    @classmethod
    def delete(cls):
        cls.get.delete()

class MainFront(WebHandler):
    def get(self):
        print secret
        self.render('front.html')

class FriendsPage(WebHandler):
    def get(self):
        if self.user:
            recieved = [f.from_user for f in Friends.recieved(self.user)]
            online = Friends.online(self.user)
            offline = Friends.offline(self.user)
            sent = [f.to_user for f in Friends.sent(self.user)]

            # print [rec.from_user.name for rec in recieved]
            # print [on.name for on in online]
            # print [off.name for off in offline]
            # print [snt.to_user.name for snt in sent]

            self.render("friends.html", online = online, offline = offline, recieved = recieved, sent = sent)
        else:
            self.redirect("/login")

class NewFriend(WebHandler):
    def get(self):
        if self.user:
            self.render("newfriend.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        target_input = self.request.get('target')

        if target_input:
            target_user = User.by_name(target_input)
            
            if target_user:

                if target_user.name != self.user.name:
                        
                        accepted = [user for user in Friends.friends(self.user) if user.name == target_user.name]
                        recieved = [target for target in Friends.recieved(self.user) if target.to_user.name == self.user.name and target.from_user.name == target_user.name]
                        sent = [target.to_user for target in Friends.sent(self.user) if target.to_user.name == target_user.name and target.from_user.name == self.user.name]

                        # print [acc.name for acc in accepted]
                        # print [rec.from_user.name for rec in recieved]
                        # print [snt.name for snt in sent]
                        # return

                        if accepted:
                            return self.render("newfriend.html", status="accepted", target=target_input)

                        elif recieved:
                            for friendships in recieved:
                                friendships.status = True
                                friendships.put()
                            return self.render("newfriend.html", status="recieved", target=target_input)

                        elif sent:
                            return self.render("newfriend.html", status="past_sent", target=target_input)

                        else:
                            f = Friends(from_user = self.user, to_user = target_user, status = False)
                            f.put()
                            return self.render("newfriend.html", status="new_sent", target=target_input)

                else:
                    error = "Cannot send an invite to be friends with yourself."
                    self.render("newfriend.html", error=error)
            else:
                error = "User with the given username, does not exist."
                self.render("newfriend.html", target_input=target_input, error=error)
        else:
            error = "Enter the username, to send an invite to be friends."
            self.render("newfriend.html", target_input=target_input, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(WebHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.online = True
            u.put()

            self.login(u)
            self.redirect('/')

class Login(WebHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(WebHandler):
    def get(self):
        if self.user:
            User.logout(self.user)
        self.logout()
        self.redirect('/')

app = webapp2.WSGIApplication([('/?', MainFront),
                               ('/friends', FriendsPage),
                               ('/newfriend', NewFriend),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
