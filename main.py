import os
import re
import random
import hashlib
import hmac
import string
from collections import namedtuple
from time import sleep
from config import SECRET

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def datetimeformat(value, format='%d %B %Y'):
    return value.strftime(format)

jinja_env.filters['datetimeformat'] = datetimeformat


class BlogHandler(webapp2.RequestHandler):
    """ Parent handler class for all pages. """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        params["user"] = self.user
        if self.user:
            # Pass user id to View
            params["user_id"] = get_user_id(self.user)
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


# Used namedtuple to pass information to the View
Post = namedtuple('Post',
                  'author post post_id like_counter was_liked comment_counter')
Comm = namedtuple('Comm', "author comment comment_id")


class MainPage(BlogHandler):
    """ Handles main page. """

    def get(self):
        blog_posts = get_all_posts()

        # Create a list of tuples Post to pass it to the View.
        posts = []
        for post in blog_posts:
            post.content = post.content.replace('\n', '<br>')
            author = get_name_by_id(post.author_id)
            post_id = get_post_id(post)

            likes = get_all_likes(post_id)
            like_counter = len(list(likes))
            liker_ids = [like.user_id for like in likes]
            was_liked = False

            comments = get_all_comments(post_id)
            comment_counter = len(list(comments))
            if self.user and \
                    self.user_id != post.author_id and \
                    self.user_id in liker_ids:
                was_liked = True
            posts.append(
                Post(
                    author=author, post=post, post_id=post_id,
                    like_counter=like_counter, was_liked=was_liked,
                    comment_counter=comment_counter
                )
            )
        self.render("main.html", posts=posts)


class NewPost(BlogHandler):
    """ Allows logged user to create a post. """

    def render_form(self, subject="", content="", error=""):
        if self.user:
            self.render("create_post.html", subject=subject,
                        content=content, error=error)
        else:
            self.redirect("/login")

    def get(self):
        self.render_form()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            # write to db
            new_post_id = create_post(title=subject, content=content,
                                      author_id=self.user_id)
            self.redirect("/" + str(new_post_id))
        else:
            error = "Fill all fields"
            self.render_form(subject, content, error)
    pass


class EditPost(BlogHandler):
    """ Allows the author of a blog post to edit it. """

    def get(self):
        post_id = int(self.request.get("post_id"))
        post = get_post_by_id(post_id)
        if self.user_id and self.user_id == post.author_id:
            subject = post.title
            content = post.content
            self.render("edit_post.html", subject=subject,
                        content=content, post_id=post_id)
        else:
            self.write("Only author can edit his/her own post!")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        post_id = int(self.request.get("post_id"))
        if subject and content and post_id:
            # write to db
            update_post(post_id=post_id, title=subject, content=content)
            self.redirect("/%s" % post_id)
        else:
            error = "Fill all fields"
            self.render("edit_post.html", subject=subject, content=content, error=error)


class DeletePost(BlogHandler):
    """ Allows the author of a blog post to delete it. """

    def get(self):
        post_id = int(self.request.get("post_id"))
        post = get_post_by_id(post_id)
        if self.user_id and post and self.user_id == post.author_id:
            delete_post(post_id)
            sleep(0.1)
            self.redirect("/")
        else:
            self.write("Only author can delete his/her own post!")


class ViewPost(BlogHandler):
    """
    Shows certain blog post in separate page with all its likes and comments.
    """

    def render_post(self, post_id, error=""):
        post = get_post_by_id(post_id)

        if post:
            post.content = post.content.replace('\n', '<br>')
            raw_comments = get_all_comments(post_id)

            # Create a list of tuples Comm for using in the View.
            comments = []
            for comment in raw_comments:
                comment.content = comment.content.replace("\n", "<br>")
                author = get_name_by_id(comment.user_id)
                comments.append(
                    Comm(
                        author=author, comment=comment,
                        comment_id=get_comment_id(comment)
                    )
                )

            # Show number of likes and whether the user liked this post or not.
            likes = get_all_likes(post.key().id())
            like_counter = len(list(likes))
            liker_ids = [like.user_id for like in likes]
            was_liked = False
            if self.user and \
                    self.user_id != post.author_id and \
                    self.user_id in liker_ids:
                was_liked = True

            author = get_name_by_id(post.author_id)

            self.render("view_post.html", author=author, post=post,
                        post_id=post_id, like_counter=like_counter,
                        was_liked=was_liked, comments=comments,
                        error=error)
        else:
            self.redirect("/")

    def get(self, post_id):
        post_id = int(post_id)
        self.render_post(post_id)

    def post(self, post_id):
        """ Handles form for comments in permalink. """
        post_id = int(post_id)
        if self.user_id:
            content = self.request.get("content")
            error = "Write your comment"
            if content:
                create_comment(user_id=self.user_id, post_id=post_id,
                               content=content)
                sleep(0.1)
                self.redirect("/%s" % post_id)
            else:
                self.render_post(post_id=post_id, error=error)
        else:
            self.redirect("/login")


class Signup(BlogHandler):
    """ Handles registration page. """
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
            params['error_username'] = "That's not a valid username"
            have_error = True

        if is_username_exist(input_username):
            params['error_username'] = "Such name already exists"
            have_error = True

        if not valid_password(input_password):
            params['error_password'] = "That wasn't a valid password"
            have_error = True

        elif input_password != input_verify:
            params['error_verify'] = "Your passwords didn't match"
            have_error = True

        if not valid_email(input_email):
            params['error_email'] = "That's not a valid email"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            # write name to db and redirect to welcome page
            salt = make_salt()
            pw_hash = make_pw_hash(input_username, input_password, salt)
            new_user_id = str(
                create_user(
                    username=input_username, pw_hash=pw_hash, salt=salt
                )
            )
            # set cookie and redirect
            self.set_secure_cookie("user_id", new_user_id)
            self.redirect("/welcome")


class Login(BlogHandler):
    """ Handles log in page. """

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
    """ Handles link for log out. """
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/signup")


class Welcome(BlogHandler):
    """ Handles the welcome page. """
    def get(self):
        if self.user:
            self.render("welcome.html", username=self.username)
        else:
            self.redirect("/signup")


class LikePost(BlogHandler):
    """ Handles like link. """

    def get(self):
        post_id = int(self.request.get("post_id"))

        # Remember to which page to return.
        source = self.request.get("source")

        post = get_post_by_id(post_id)
        likes = get_all_likes(post_id)
        liker_ids = [like.user_id for like in likes]
        if not self.user:
            self.redirect("/login")
        if self.user:
            # If user already liked this post - remove like, otherwise add.
            if self.user_id != post.author_id:
                if self.user_id in liker_ids:
                    delete_like(self.user_id, likes)
                else:
                    create_like(self.user_id, post_id)
            sleep(0.1)
            self.redirect("/" + source)


class EditComment(BlogHandler):
    """ Allows user to edit his/her comment on the separate page. """

    def get(self):
        comment_id = int(self.request.get("comment_id"))
        comment = get_comment_by_id(comment_id)
        if self.user_id and comment and self.user_id == comment.user_id:
            content = comment.content
            self.render("edit_comment.html", content=content,
                        comment_id=comment_id, post_id=comment.post_id)
        else:
            self.write("Only author can edit his/her own post!")

    def post(self):
        content = self.request.get("content")
        comment_id = int(self.request.get("comment_id"))
        if content and comment_id:
            # write to db
            update_comment(comment_id, content)
            sleep(0.1)
            self.redirect("/%s" % get_comment_by_id(comment_id).post_id)
        else:
            error = "Comment can't be empty"
            self.render("edit_comment.html", content=content, error=error)


class DeleteComment(BlogHandler):
    """ Handles link for removing user's comment. """

    def get(self):
        comment_id = int(self.request.get("comment_id"))
        comment = get_comment_by_id(comment_id)
        post_id = comment.post_id
        if self.user_id and comment and self.user_id == comment.user_id:
            delete_comment(comment_id)
            sleep(0.1)
            self.redirect("/%s" % post_id)
        else:
            self.write("Only author can delete his/her own post!")


# DB ENTITIES
class BlogPost(db.Model):
    """ Represents user's blog post. """

    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class User(db.Model):
    """ Represents a user. """
    username = db.StringProperty(required=True)
    hash = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)


class Like(db.Model):
    """ Represents like for a blog post. """
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)


class Comment(db.Model):
    """ Represents comment for a blog post. """
    content = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# DB calls
# User repository
def get_name_by_id(user_id):
    """
    Finds user's nickname in db.
    Args:
        user_id: Integer, user's id in db.
    Returns:
        String that represents user's nickname.
    """
    return User.get_by_id(user_id).username


def get_user_by_name(name):
    """ Returns user by his/her nickname. """
    return User.all().filter('username =', name).get()


def create_user(username, pw_hash, salt):
    """
    Create a new user in db.
    Args:
        username: String with unique user's nickname.
        pw_hash: String, generated has of user's password.
        salt: String, auto generated secret word.
    Returns:
        Integer, generated by db user's id.
    """
    new_user = User(username=username, hash=pw_hash, salt=salt)
    new_user.put()
    return get_user_id(new_user)


def get_user_id(user):
    """ Find specific user id. """
    return user.key().id()


# Post repository
def get_all_posts():
    """ Returns all posts ordered by date created. """
    return BlogPost.all().order('-created')


def create_post(title, content, author_id):
    """
    Adds new post in db.
    Args:
        title: String, the topic of blog post.
        content: String, text of blog post.
        author_id: Integer, associated with author id from User table.
    Returns:
        Integer, generated id of created blog post.
    """
    new_post = BlogPost(title=title, content=content, author_id=author_id)
    new_post.put()
    return get_post_id(new_post)


def update_post(post_id, title, content):
    """
    Changes specific post in db.
    Args:
        post_id: Integer, id of blog post.
        title: String, the topic of blog post.
        content: String, text of blog post.
    """
    post = get_post_by_id(post_id)
    if post:
        post.title = title
        post.content = content
        post.put()


def delete_post(post_id):
    """
    Delete post and all associated with it likes and comments
    Args:
        post_id: Integer that represents id of blog post.
    """
    post = get_post_by_id(post_id)
    if post:
        post.delete()
        likes = get_all_likes(post_id)
        for like in likes:
            like.delete()
        comments = get_all_comments(post_id)
        for comment in comments:
            comment.delete()


def get_post_id(post):
    """ Returns id for specific post. """
    return post.key().id()


def get_post_by_id(post_id):
    """
    Finds specific post in db by it's id.
    Args:
        post_id: Integer, id of the post given by db.
    Returns:
        Specific blog post.
    """
    return BlogPost.get_by_id(post_id)


# Like repository
def create_like(user_id, post_id):
    """
    Adds new like to db.
    Args:
        user_id: Integer, id of the user who liked post.
        post_id: Integer, id of the post that was liked.
    """
    new_like = Like(user_id=user_id, post_id=post_id)
    new_like.put()


def delete_like(user_id, likes):
    """
    Delete specific like from db.
    Args:
        user_id: Integer, id of the user who removed his/her like
        likes: List of likes for specific blog post.
    """
    like_to_delete = likes.filter("user_id =", user_id).get()
    like_to_delete.delete()


def get_all_likes(post_id):
    """
    Retrieves all likes associated with certain blog post.
    Args:
        post_id: Integer that represents blog post id.
    Returns:
         List of likes for certain blog post.
    """
    return Like.all().filter("post_id =", post_id)


# Comment repository
def get_comment_id(comment):
    """ Returns id for specific comment. """
    return comment.key().id()


def get_all_comments(post_id):
    """
    Retrieves all comments associated with certain blog post.
    Args:
        post_id: Integer that represents blog post id.
    Returns:
         List of all comments ordered by time created.
    """
    return Comment.all().filter("post_id =", post_id).order("-created")


def create_comment(user_id, post_id, content):
    """
    Adds new comment to db.
    Args:
        user_id: Integer, id of the user who commented the post.
        post_id: Integer, id of the post which was commented.
        content: String, text of the comment.
    """
    new_comment = Comment(user_id=user_id, post_id=post_id, content=content)
    new_comment.put()


def update_comment(comment_id, content):
    """
    Updates the specific comment in db.
    Ars:
        comment_id: Integer, id of the specific comment.
        content: String, updated text of the comment.
    """
    comment = get_comment_by_id(comment_id)
    if comment:
        comment.content = content
        comment.put()


def get_comment_by_id(comment_id):
    """ Returns specific comment by it's id. """
    return Comment.get_by_id(comment_id)


def delete_comment(comment_id):
    """
    Delete specific comment from db.
    Args:
        comment_id: Integer, id of comment that should be removed.
    """
    comment = get_comment_by_id(comment_id)
    if comment:
        comment.delete()


# Cookie security
def hash_str(s):
    """
    Creates hash for specific s with secret word.
    Args:
        s: String that should be encrypted.
    Returns:
        Hash.
    """
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    """ Combines value and its hash. """
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    """
    Check if value matches generated hash.
    Args:
        h: String, combination of value and its hash.
    Returns:
        String value if it matches the hash.
    """
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val


# Password security
def make_salt():
    """ Auto generates secret word. """
    return ''.join(random.choice(string.letters) for x in range(0, 15))


def make_pw_hash(name, pw, salt):
    """
    Generates hash for user's password.
    Args:
        name: String, user's nickname.
        pw: String, user's password.
        salt: String, auto generated secret word.
    Returns:
        Hash.
    """
    return hashlib.sha256(name + pw + salt).hexdigest()


def valid_pw(name, pw):
    """
    Check if user's password matches its hash.
    Args:
        name: String, user's nickname
        pw: String, entered password.
    Returns:
        User if password matches.
    """
    user = get_user_by_name(name)
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
                               ('/deletepost', DeletePost),
                               ('/editpost', EditPost),
                               ('/like', LikePost),
                               ('/deletecomment', DeleteComment),
                               ('/editcomment', EditComment)
                               ],
                              debug=True)
