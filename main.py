import os
import re
import random
import hashlib
import hmac
import string
from collections import namedtuple

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


SECRET = "we-haVe_Always#Lived+in@the=CasTle!<3"


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        params["user"] = self.user
        if self.user:
            params["user_id"] = self.user.key().id()
        return t.render(params)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))
        if self.user:
            self.user_id = self.user.key().id()
            self.username = self.user.username


class MainPage(BlogHandler):
    def get(self):
        blog_posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC LIMIT 10")
        Post = namedtuple('Post', 'author post like_counter was_liked')
        posts = []
        for post in blog_posts:
            author_name = User.get_by_id(post.author_id).username
            likes = db.GqlQuery("SELECT * FROM Like WHERE post_id = %s" % post.key().id())
            like_counter = len(list(likes))
            liker_ids = [like.user_id for like in likes]
            was_liked = False
            if self.user and self.user_id != post.author_id and self.user_id in liker_ids:
                was_liked = True
            posts.append(Post(author=author_name, post=post, like_counter=like_counter, was_liked=was_liked))
        self.render("main.html", posts=posts)


class NewPost(BlogHandler):
    # if not logged in -> redirect to login page
    def render_form(self, subject="", content="", error=""):
        if self.user:
            self.render("create_post.html", subject=subject, content=content, error=error)
        else:
            self.redirect("/login")

    # the form input boxes must have the names 'subject' and 'content'
    def get(self):
        self.render_form()

    #  After submitting a blog post, I ask you to redirect to a permalink for that post.
    # The URL format might look something like this: /blog/1001,
    # where 1001 is the ID of the post you just submitted.
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            # write to db
            new_post = BlogPost(title=subject, content=content, author_id=self.user_id)
            new_post.put()
            self.redirect("/" + str(new_post.key().id()))
        else:
            error = "Fill all fields"
            self.render_form(subject, content, error)
    pass


class EditPost(BlogHandler):
    def get(self):
        post_id = int(self.request.get("post_id"))
        post = BlogPost.get_by_id(post_id)
        if self.user_id and self.user_id == post.author_id:
            subject = post.title
            content = post.content
            self.render("edit_post.html", subject=subject, content=content, post_id=post_id)
        else:
            self.write("Only author can edit his/her own post!")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        post_id = int(self.request.get("post_id"))
        if subject and content and post_id:
            # write to db
            post = BlogPost.get_by_id(post_id)
            post.title = subject
            post.content = content
            post.put()
            self.redirect("/" + str(post_id))
        else:
            error = "Fill all fields"
            self.render_form(subject, content, error)


class DeletePost(BlogHandler):
    def get(self):
        post_id = int(self.request.get("post_id"))
        post = BlogPost.get_by_id(post_id)
        if self.user_id and self.user_id == post.author_id:
            post.delete()
            self.redirect("/")
        else:
            self.write("Only author can delete his/her own post!")


class ViewPost(BlogHandler):
    def get(self, post_id):
        blog_post = BlogPost.get_by_id(int(post_id))
        if blog_post:
            author = User.get_by_id(blog_post.author_id).username
            self.render("view_post.html", author=author, post=blog_post, post_id=post_id)
        else:
            self.redirect("/")


class Signup(BlogHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        input_username = self.request.get('username')
        input_password = self.request.get('password')
        input_verify = self.request.get('verify')
        input_email = self.request.get('email')

        params = dict(username=input_username,
                      email=input_email)

        if not valid_username(input_username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if is_username_exist(input_username):
            params['error_username'] = "Such name already exists."
            have_error = True

        if not valid_password(input_password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif input_password != input_verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(input_email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            # write name to db
            # redirect to welcome page
            salt = make_salt()
            pw_hash = make_pw_hash(input_username, input_password, salt)
            new_user = User(username=input_username, hash=pw_hash, salt=salt)
            new_user.put()
            # set cookie and redirect
            self.set_secure_cookie("user_id", str(new_user.key().id()))
            self.redirect("/welcome")


class Login(BlogHandler):
    # if login succeed redirect to welcome page
    def get(self):
        self.render("login.html")

    def post(self):
        input_username = self.request.get('username')
        input_password = self.request.get('password')
        user = valid_pw(input_username, input_password)
        if user:
            self.set_secure_cookie("user_id", str(user.key().id()))
            self.redirect("/welcome")
            pass
        else:
            error = "Invalid login"
            params = dict(username=input_username, error=error)
            self.render('login.html', **params)


class Logout(BlogHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/signup")


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render("welcome.html", username=self.username)
        else:
            self.redirect("/signup")


class LikePost(BlogHandler):
    def get(self):
        post_id = int(self.request.get("post_id"))
        post = BlogPost.get_by_id(post_id)
        # get all likes from Like
        likes = db.GqlQuery("SELECT * FROM Like WHERE post_id = %s" % post_id)
        liker_ids = [like.user_id for like in likes]
        if self.user and self.user_id != post.author_id and self.user_id not in liker_ids:
            new_like = Like(user_id=self.user_id, post_id=post_id)
            new_like.put()
        self.redirect("/?something=nothing")


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


class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)


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
    return hashlib.sha256(name + pw + salt).hexdigest()


def valid_pw(name, pw):
    user = User.all().filter('username =', name).get()
    if user:
        salt = user.salt
        if user.hash == make_pw_hash(name, pw, salt):
            return user


# Validate entries
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def is_username_exist(name):
    users = db.GqlQuery("SELECT * FROM User")
    for user in users:
        if user.username == name:
            return name


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Routing
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Signup),
                               ('/welcome', Welcome),
                               ('/logout', Logout),
                               ('/login', Login),
                               ('/newpost', NewPost),
                               ('/(\d+)', ViewPost),
                               ('/delete', DeletePost),
                               ('/edit', EditPost),
                               ('/like', LikePost)
                               ],
                              debug=True)
