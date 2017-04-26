import os
import re
import random
import hashlib
import hmac
import string

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = "we haVe Always Lived in the CasTle!<3"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.write(render_str(template, **kw))

"""    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))"""


class MainPage(BlogHandler):
    def get(self):
        """ Show 10 newest posts"""
        self.write('Hello Blog')


class NewPost(BlogHandler):
    # if not logged in -> redirect to login page
    pass


class ViewPost(BlogHandler):
    pass


class Signup(BlogHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not unique_username(self.username):
            params['error_username'] = "Such name already exists."
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
            self.render('signup.html', **params)
        else:
            # write name to db
            # redirect to welcome page
            salt = make_salt()
            pw_hash = make_pw_hash(self.username, self.password, salt)
            new_user = User(username=self.username, hash=pw_hash, salt=salt)
            new_user.put()
            # set cookie and redirect
            self.redirect("/welcome")


class Login(BlogHandler):
    # redirect to welcome page
    pass


class Logout(BlogHandler):
    pass


class Welcome(BlogHandler):
    def get(self):
        self.render("welcome.html")


# DB ENTITIES
class BlogPost(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class User(db.Model):
    username = db.StringProperty(required=True)
    hash = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)


# Cookie security
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val


# Password security
def make_salt():
    return ''.join(random.choice(string.letters) for x in range(0, 15))


def make_pw_hash(name, pw, salt):
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(",")[1]
    return h == make_pw_hash(name, pw, salt)


# Validate entries
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def unique_username(name):
    users = db.GqlQuery("SELECT * FROM User")
    for user in users:
        print(user.username)
        if user.username == name:
            return False
    return name


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Routing
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Signup),
                               ('/welcome', Welcome)
                               ],
                              debug=True)
