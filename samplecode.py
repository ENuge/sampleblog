import os
import cgi
import re
import sys
import urllib2
from xml.dom import minidom

from string import letters

import random
import string
import hashlib
import hmac

import logging
import time
from datetime import datetime, timedelta

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

# Database Entries
class LoginData(db.Model):
    username = db.TextProperty(required = True)
    password = db.TextProperty(required = True)

class SinglePost(db.Model):
    subject = db.TextProperty(required = True) # subject of blog post
    content = db.TextProperty(required = True) # content of blog post
    created = db.DateTimeProperty(auto_now_add = True) # date of blog post



## Cookie-related hashing
def hash_str(s):
    """
    Hashes a string.
    """
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    """
    Hash a value in the format s|hash
    """
    return "%s|%s" % (s, hash_str(s))

# 
def check_secure_val(h):
    """
    Checks that the given hash matches what our hashing function gives.
    If so, return the unhashed value.
    """
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

## Password-related hashing and salting
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    """
    Hashes password using sha256 algorithm. Returns output in form "hash, salt".
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    """
    Checks if a password matches its hash.
    """
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


###### Memcached related age-getting for blog posts
def age_set(key, val):
    """
    Sets the age for a blog post.
    """
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))

def age_get(key):
    """
    Outputs the age of a blog post.
    """
    r = memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0

    return val, age

def add_post(post):
    """
    Adds a post to the database.
    """
    post.put()
    get_posts(update = True)
    return post.key().id()

def edit_post(key, subject, content):
    """
    Edits a post already in the database (keeping original date/time).
    """
    post = db.get(key)
    post.subject = subject
    post.content = content
    post.put()

def get_posts(update = False):
    """
    Gets 30 blog posts for the front page.
    """
    q = SinglePost.all().order('-created').fetch(limit = 30)
    mc_key = 'BLOGS'
    posts, age = age_get(mc_key)

    if update or posts is None:
        posts = list(q)
        age_set(mc_key, posts)

    return posts, age

def age_str(age):
    """
    Formats our timequery nicely.
    """
    s = 'queried %s seconds ago'
    age = int(age)
    if age == 1:
        s = s.replace('seconds', 'second')
    return s % age


#### sampleuser hard-coded as only valid username/password.
#### Signup page disabled.
pwhash = make_pw_hash("sampleuser", "samplepassword")
l = LoginData(username = "sampleuser", password = pwhash)
l_key = l.put()


# Note that this should be in a separate file, but this is just code to 
# demonstrate how it works, in general.
SECRET = 'generichash' # 'Secret' hash for our passwords

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))
# autoescape = True commented out so blog can use HTML formatting




class Handler(webapp2.RequestHandler):
    """
    Generic handler that gets passed to each subsequent class.
    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


####### Start of the static webpages
class Welcome(Handler):
    """
    A very basic welcome splash page for me when I log in.
    """
    def render_welcome(self, username=""):
        self.render("welcome.html", username = user_cookie_str)

    def get(self):
        usercookie = self.request.cookies.get('username')

        if usercookie:
            user_cookie_str = check_secure_val(usercookie)
            if user_cookie_str:
                self.render("welcome.html", username = user_cookie_str)
        elif not usercookie or not user_cookie_str:
            self.redirect('/')


class MainPage(Handler):
    """
    The homepage, or about me, for the website.
    """
    def get(self):
        self.render("home.html")


class Projects(Handler):
    """
    Details projects that I am working on.
    """
    def get(self):
        self.render("projects.html")


class Resume(Handler):
    """
    Renders my resume. The HTML was generated using a PDF-to-HTML tool online,
    but then modified a bit to look nice on the page.
    """
    def get(self):
        self.render("resume.html")


class Contact(Handler):
    """
    Gives information for how one may contact me.
    """
    def get(self):
        self.render("contact.html")


####### Start of the blog-related webpages, etc.
class Login(Handler):
    """
    Login page allows me to login using the only valid username/password.
    """
    def render_login(self, username="",
                     usererror="", password="", passworderror=""):
        self.render("login.html", username = username, usererror = usererror,
                    password = password, passworderror = passworderror)

    def get(self):
        self.render_login()

    def post(self):
        username = str(self.request.get("username"))
        password = str(self.request.get("password"))

        usererror = ""
        passworderror = ""

        usercookie = str(make_secure_val(username))

        # check if the username and corresponding password
        # are in the database; if so, redirect them to the login page
        # otherwise, throw an error

        if checkdb(username) == False and verifypwd(username, password):
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header('Set-Cookie',
                                         'username=' + usercookie + '; Path=/')
            self.redirect("/welcome")

        if checkdb(username):
            usererror = "This is not a valid username!"
            self.render_login(username, usererror, password, passworderror)

        if (verifypwd(username, password) == False and 
            checkdb(username)==False):
            passworderror = "Wrong password!"
            self.render_login(username, usererror, password, passworderror)


class Logout(Handler):
    """
    Logout page allows me to logout and wipe the cookies.
    """
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header('Set-Cookie',
                                'username=; Path=/'
                                '; expires=Sun, 16-Jul-2012 23:59:59 GMT')
        self.redirect('/')


class Flush(Handler):
    """
    If the user is logged in, he may flush memcached by going to this 
    URL.
    """
    def get(self):
        usercookie = self.request.cookies.get('username')
        if usercookie:
            user_cookie_str = check_secure_val(usercookie)
            if user_cookie_str:
                memcache.flush_all()
                self.redirect('/')
        elif not usercookie or not user_cookie_str:
            self.redirect('/')


class Blog(Handler):
    """
    Renders the front page for the blog, showing the latest 30 blog posts.
    """
    def render_blog(self, subject="", content="", error="", created=""):
        posts, timequery = get_posts(True) # also updates the db

        self.render("blog.html", posts=posts, timequery=age_str(timequery))
    
    def get(self):
        self.render_blog()


class NewPost(Handler):
    """
    Allows the user to submit a new blog post.
    """
    def render_newpost(self, subject="", content="", error=""):
        self.render("newpost.html", subject = subject,
                    content = content, error = error)
    
    def get(self):
        usercookie = self.request.cookies.get('username')
        if usercookie:
            user_cookie_str = check_secure_val(usercookie)
            if user_cookie_str:
                self.render_newpost()
        elif not usercookie or not user_cookie_str:
            self.redirect('/')

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            s = SinglePost(subject = subject, content = content)
            s_id = add_post(s) # returns id of created post

            self.redirect("/%d" % s_id)
        else:
            error = "you need both a subject and a body!"
            self.render_newpost(subject, content, error)


class PermaLink(Handler):
    """
    Unique webpage for each specific blog post.
    """
    def render_post(self, subject="", content="", created="", webURL="",
                    timequery="", edit=""):
        self.render("singlepost.html", subject = subject, content = content,
                    created = created, webURL = webURL, timequery = timequery,
                    edit = edit)

    def get(self, postid):
        post_key = 'POST_' + postid # key used for memcached
        post, age = age_get(post_key) # gets age of posts from cache

        try:            # if given URL is not numeric (and not any other page)
            int(postid) # then it is invalid, so redirect to the home page
        except ValueError: 
            self.redirect('/')
            return

        if not post: # if post not in cache, get it from database
            key = db.Key.from_path('SinglePost', int(postid))
            post = db.get(key)
            age_set(post_key, post) # then put it in the cache
            age = 0

        if not post: # if no post with this id, then invalid URL
            self.error(404)
            return

        s = SinglePost.get_by_id(int(postid))
        usercookie = self.request.cookies.get('username')

        if usercookie: 
            user_cookie_str = check_secure_val(usercookie)
            if user_cookie_str:
                self.render_post(subject = s.subject, content = s.content,
                                 created = s.created, webURL = s.key().id(),
                                 timequery = age_str(age), edit = True)    

        if not usercookie or not user_cookie_str:
            self.render_post(subject = s.subject, content = s.content,
                             created = s.created, webURL = s.key().id(),
                             timequery = age_str(age), edit = False) 


class EditPage(Handler):
    """
    Allows one to edit a specific blog post.
    """
    def render_edit(self, subject="", content="", error="", timequery=""):
        self.render("edit.html", subject = subject, content = content,
                    error = error, timequery = timequery)
    
    def get(self, postid):
        logging.error(postid)
        post_key = 'POST_' + postid

        post, age = age_get(post_key)

        postid=postid[1:]
        try:
            int(postid)
        except ValueError:
            self.error(404)
            return

        if not post:
            key = db.Key.from_path('SinglePost', int(postid))
            post = db.get(key)
            age_set(post_key, post)
            age = 0

        if not post:
            self.error(404)
            return

        s = SinglePost.get_by_id(int(postid))
        usercookie = self.request.cookies.get('username')

        if usercookie: 
            user_cookie_str = check_secure_val(usercookie)
            if user_cookie_str:
                self.render_edit(subject=s.subject, content=s.content,
                                 timequery=age_str(age))          
        if not usercookie or not user_cookie_str:
            self.redirect('/')

        
    def post(self, postid):
        subject = self.request.get("subject")
        content = self.request.get("content")
        postid = postid[1:]

        if subject and content:
            key = db.Key.from_path('SinglePost', int(postid))
            edit_post(key, subject, content)
            
            self.redirect("/%d" % int(postid))
        else:
            error = "you need both a subject and a body!"
            self.render_edit(subject, content, error, age_str(0))


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/welcome', Welcome), ('/', MainPage),
                               ('/projects', Projects), ('/resume', Resume),
                               ('/contact', Contact), ('/login', Login),
                               ('/logout', Logout), ('/flush', Flush),
                               ('/blog', Blog), ('/newpost', NewPost),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/(\S+)', PermaLink)], 
                               debug = True)


def checkdb(username):
    """
    Checks if our username is already in the database.
    If so, return False.
    """
    dbuser = db.GqlQuery("SELECT * FROM LoginData")
                         #"WHERE username = :user",
                         #user=username)
    for x in dbuser:
        if x.username == username:
            return False
    return True


# Verifypwd checks if the input password matches the hashed value saved
# in the database.
def verifypwd(username, password):
    """
    Checks if the input password matches the hashed value saved in the
    database.
    """
    dbuser = db.GqlQuery("SELECT * FROM LoginData")

    for x in dbuser:
        if x.username == username:
            pwhash = str(x.password)
            return valid_pw(username, password, pwhash)
    return False