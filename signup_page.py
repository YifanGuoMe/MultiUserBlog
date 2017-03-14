 #!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import sys
import os
import webapp2
import jinja2
import re
import hmac
import random
import hashlib
from string import letters
from google.appengine.ext import db
import logging

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
    autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
    
# define a parent object for all blogs in google database
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    blog = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.StringProperty(required = True)

    @classmethod
    def new_blog(cls, subject, blog, user_id):
        return Blog(subject = subject, blog = blog, user_id = user_id)

    #render blog entry
    def render(self):
        self._render_text = self.blog.replace('\n', '<br>')
        return render_str("post.html", b=self)
        # return render_str("post.html", self.subject,self.blog, self.created, self.last_modified)


# HMAC to hash user id
secret = "haha"
def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Hashing salt to hash the password
def make_salt(length=5):
    return ''.join(random.choice(letters) for i in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt(5)
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# definition of valid username password and email address
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)


# define a user class for user datebase
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.EmailProperty(required = False)

    # email = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        return User.all().filter('name =', name).get()

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name, pw_hash = pw_hash, email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# general handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # render basic template
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    #set cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))
    
    # read cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def log_in(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def log_out(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def get_user(self):
        uid = self.read_secure_cookie('user_id')
        return User.by_id(long(uid))


    # def initialize(self, *a, **kw):
    #     webapp2.RequestHandler.initialize(self, *a, **kw)
    #     uid = self.read_secure_cookie('user_id')
    #     self.user = uid and User.by_id(int(uid))

# Generate the first front page which lists most latest blogs
class FrontPageHander(Handler):
    def get(self):
        # get all posts 
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 10")
        self.render("front_page.html", blogs = blogs)


class NewPostHandler(Handler):
    def get(self):
        self.render("new_post.html")

    def post(self):
        # user = User.by_id(long(uid))
        subject = self.request.get("subject")
        blog = self.request.get("blog")
        created_user = self.get_user()
        uid = self.read_secure_cookie('user_id')

        if subject and blog:
            # create a new blog
            b = Blog.new_blog(subject, blog, uid)
            # b = Blog(parent = blog_key(), subject = subject, blog = blog)
            b.put()
            self.redirect("/blog/%s" % str(b.key().id()))
        else: 
            error = "subject and content, please!"        
            self.render("new_post.html", error=error, subject_line=subject, blog_text=blog)

# a perticular post
class PostedHandler(Handler):
    def get(self, blog_id):
        # key = db.Key.from_path('Blog', int(blog_id), parent= blog_key())
        key = db.Key.from_path('Blog', int(blog_id))
        blog = db.get(key)

        if not blog:
            self.error(404)
            return
        self.render("post_result.html", blog = blog)

class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        # import pdb; pdb.set_trace()
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        invalid_username_error = ""
        invalid_password_error = ""
        mismatch_password_error = ""
        invalid_email_error = ""

        req_condition = valid_username(username) and valid_password(password) and password == verify
        

        if (req_condition and not email) or (req_condition and email and valid_email(email)):
           # add the new user to database
            # import pdb; pdb.set_trace()
            u_exist = User.by_name(username)
            if not u_exist:
                
                new_user = User.register(username, password, email)
                new_user.put()
                # import pdb; pdb.set_trace()
                self.set_secure_cookie('user_id', str(new_user.key().id()))
                self.redirect("/welcome") 
            else:
                invalid_username_error = "That user already exists"
                self.render("signup.html", username=username, user_name=username,
                email=email, email_address=email,
                invalid_username = invalid_username_error, 
                invalid_password = invalid_password_error,
                mismatch_password = mismatch_password_error,
                invalid_email = invalid_email_error)                        
        else: 
            if not valid_username(username):
                invalid_username_error = "That's not a valid username."
            if not valid_password(password):
                invalid_password_error = "That wasn't a valid password."
            if password != verify:
                mismatch_password_error = "Your passwords didn't match."
            if email and not valid_email(email):
                invalid_email_error = "That's not a valid email."
            self.render("signup.html", username=username, user_name=username, 
                email=email, email_address=email,
                invalid_username = invalid_username_error, 
                invalid_password = invalid_password_error,
                mismatch_password = mismatch_password_error,
                invalid_email = invalid_email_error)

class Welcome(Handler):
    def get(self):
        uid = self.read_secure_cookie('user_id')
        username = User.by_id(long(uid)).name
        if valid_username(username) and uid:
            self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        login_user = User.login(username, password)
        # import pdb; pdb.set_trace()
        if login_user:
            self.log_in(login_user)
            # self.set_secure_cookie('user_id', str(user_.key().id()))
            self.redirect("/blog")
        else:
            self.redirect('/signup')
        #     msg = 'Invalid login'
        #     self.render('login-form.html', error = msg)

class Logout(Handler):
    def get(self):
        self.log_out()
        self.redirect('/login')
     
app = webapp2.WSGIApplication([
    ('/signup', Signup), 
    ('/welcome', Welcome), 
    ('/login', Login),
    ('/logout', Logout),
    ('/blog/?', FrontPageHander),
    ('/blog/([0-9]+)', PostedHandler),
    ('/blog/newpost', NewPostHandler)
], debug=True)