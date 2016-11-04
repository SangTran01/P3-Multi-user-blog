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
import webapp2
import jinja2
import os
import hmac
import re

from user import User
from user import make_pw_hash
from post import Post
from comment import Comment

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


secret = 'dog'

# create and secure cookie


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def read_secure_cookie(cookie_val):
    return cookie_val and check_secure_val(cookie_val)


def check_LikeOrDislike(current_u, post):
    if current_u.username in post.users_liked:
        return 1
    elif current_u.username in post.users_disliked:
        return 2
    else:
        return 0

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def send_back(self):
        self.redirect('/register')
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def logout(self):
        self.redirect('/blog')
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class MainHandler(BlogHandler):

    def get(self):
        self.render('base.html')


class Register(BlogHandler):

    def get(self):
        self.render('register.html')

    def post(self):
        has_errors = False
        errors = {}
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        if not valid_username(username):
            errors["error_username"] = "Invalid Username"
            has_errors = True

        if not valid_password(password):
            errors["error_password"] = "Invalid Password"
            has_errors = True

        if password != verify:
            errors["error_verify"] = "Passwords don't match"
            has_errors = True

        if not valid_email(email):
            errors["error_email"] = "Invalid Email"
            has_errors = True

        if has_errors:
            self.render("register.html", **errors)
        else:
            # set cookie and create user object
            # check if another same name user
            u = User.by_name(username)
            if u:
                msg = 'That user already exists.'
                self.render('register.html', error_username=msg)
            else:
                pw_hash = make_pw_hash(username, password)
                u = User(username=username, pw_hash=pw_hash, email=email)
                uput = u.put()
                # long object
                uid = uput.id()
                secure_val = make_secure_val(str(uid))
                # user = User.get_by_id(uid)
                self.response.headers.add_header(
                    'Set-Cookie', '%s=%s; Path=/' % ('user_id', secure_val))
                # self.write(user.username)
                # set cookie
                self.redirect('/welcome')


class Login(BlogHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        valid_user = User.login(username, password)
        if valid_user:
            self.login(valid_user)
            self.redirect('/blog')
        else:
            error = "Invalid Username or Password"
            self.render("login.html", error_message=error)


class Logout(BlogHandler):

    def get(self):
        self.logout()


class Permalink(BlogHandler):

    def get(self):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                self.render('permalink.html', username=current_u.username)
            else:
                self.send_back()

        else:
            self.send_back()


class Blog(BlogHandler):

    def get(self):
        # if registered or logged in
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                # get all posts
                posts = db.GqlQuery(
                    "SELECT * from Post ORDER BY created DESC limit 10")
                self.render(
                    'blog.html', username=current_u.username, posts=posts)
            else:
                self.send_back()

        # render view for visiter
        else:
            posts = db.GqlQuery(
                "SELECT * from Post ORDER BY created DESC limit 10")
            self.render('blog.html', posts=posts)


class Newpost(BlogHandler):

    def get(self):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                self.render(
                    'newpost.html', username=current_u.username, uid=uid)
            else:
                self.send_back()

        else:
            self.send_back()

    def post(self):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                # getting inputs after confirming user
                subject = self.request.get('subject')
                content = self.request.get('content')

                if subject and content:
                    p = Post(
                        subject=subject, content=content,
                        created_by=current_u.username)
                    pput = p.put()
                    # redirect to that post
                    # pass a post cookie?
                    self.redirect('/blog/%s' % str(pput.id()))
                else:
                    error = "Sorry. A post needs a subject and content"
                    self.render(
                        'newpost.html',
                        error=error,
                        subject=subject,
                        content=content)

            else:  # end of uid
                self.send_back()

        else:  # end of cookie_val
            self.send_back()


class Postpage(BlogHandler):

    def get(self, post_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                if post:
                    # declare comments dict key = property, value= value
                    # list of dictionaries
                    comments_list = []
                    for comments_keys in post.comments:
                        comment = db.get(comments_keys)
                        comment_dic = {}
                        # check for NoneType
                        if comment is not None:
                            comment_dic['content'] = comment.content
                            comment_dic['created_by'] = comment.created_by
                            comment_dic['id'] = comments_keys.id()
                            comment_dic['created'] = comment.created
                            comments_list.append(comment_dic)
                    # sort list by created
                    comments_list = sorted(
                        comments_list, key=lambda k: k['created'],
                        reverse=True)
                    self.render(
                        'postpage.html',
                        username=current_u.username,
                        post=post,
                        comments=comments_list)
                else:
                    self.redirect('/blog')
            else:
                self.send_back()

        else:
            self.send_back()


class Editpost(BlogHandler):

    def get(self, post_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                if post and current_u.username == post.created_by:
                    self.render(
                        'editpost.html',
                        username=current_u.username,
                        post_id=post_id,
                        post=post)
                else:
                    self.redirect('/blog')
            else:
                self.send_back()

        else:
            self.send_back()

    def post(self, post_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                # getting inputs after confirming user
                subject = self.request.get('subject')
                content = self.request.get('content')

                if subject and content:
                    # still had post id in url so I used it to get post obj
                    # couldn't think of another way
                    post = Post.get_by_id(int(post_id))
                    post.subject = subject
                    post.content = content
                    pput = post.put()
                    # redirect to that post
                    # pass a post cookie?
                    self.redirect('/blog/%s' % str(pput.id()))
                else:
                    error = "a post needs a subject and content"
                    self.render('newpost.html', error=error)

            else:  # end of uid
                self.send_back()

        else:  # end of cookie_val
            self.send_back()


class Deletepost(BlogHandler):

    def get(self, post_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                if post and current_u.username == post.created_by:
                    post.delete()
                    self.render('delete.html')
                else:
                    self.redirect('/blog')
            else:
                self.send_back()

        else:
            self.send_back()


class Likepost(BlogHandler):

    def get(self, post_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                if post and current_u.username != post.created_by:
                    # new_user = True
                    # check user liked/dislike
                    # 	return 1 if liked
                    # 	return 2 if disliked
                    # 	return 0 if new
                    status = check_LikeOrDislike(current_u, post)
                    if status == 1:
                        error = "Sorry. You already liked this!"
                        posts = db.GqlQuery(
                            "SELECT * from Post "
                            "ORDER BY created DESC limit 10")
                        self.render(
                            'blog.html',
                            username=current_u.username,
                            posts=posts,
                            error=error)
                    elif status == 2:
                        post.users_disliked.remove(current_u.username)
                        post.users_liked.append(current_u.username)
                        post.likes += 1
                        post.put()
                        self.redirect('/blog')
                    elif status == 0:
                        post.users_liked.append(current_u.username)
                        post.likes += 1
                        post.put()
                        self.redirect('/blog')
                else:
                    self.redirect('/blog')
            else:
                self.send_back()

        else:
            self.send_back()


class Dislikepost(BlogHandler):

    def get(self, post_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                if post and current_u.username != post.created_by:
                    # new_user = True
                    # check user liked/dislike
                    # 	return 1 if liked
                    # 	return 2 if disliked
                    # 	return 0 if new
                    status = check_LikeOrDislike(current_u, post)
                    if status == 2:
                        error = "Sorry. You already disliked this!"
                        posts = db.GqlQuery(
                            "SELECT * from Post "
                            "ORDER BY created DESC limit 10")
                        self.render(
                            'blog.html',
                            username=current_u.username,
                            posts=posts,
                            error=error)
                    elif status == 1:
                        post.users_liked.remove(current_u.username)
                        post.users_disliked.append(current_u.username)
                        post.likes -= 1
                        post.put()
                        self.redirect('/blog')
                    elif status == 0:
                        post.users_disliked.append(current_u.username)
                        post.likes -= 1
                        post.put()
                        self.redirect('/blog')
                else:
                    self.redirect('/blog')
            else:
                self.send_back()

        else:
            self.send_back()


class CommentPage(BlogHandler):

    def get(self, post_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                if post:
                    self.render(
                        'newcomment.html',
                        username=current_u.username,
                        post_id=post_id)
                else:
                    self.redirect('/blog')
            else:
                self.send_back()

        else:
            self.send_back()

    def post(self, post_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                if post:
                    content = self.request.get('content')
                    if content:
                        c = Comment(
                            content=content,
                            created_by=current_u.username)
                        cput = c.put()
                        post.comments.append(c.key())
                        post.put()
                        self.redirect('/blog/%s' % post_id)
                    else:
                        error = "Sorry. Looks like you're missing content"
                        self.render(
                            'newcomment.html',
                            username=current_u.username,
                            error=error)

                else:
                    self.redirect('/blog')
            else:
                self.send_back()

        else:
            self.send_back()


class EditComment(BlogHandler):

    def get(self, post_id, comment_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                comment = Comment.get_by_id(int(comment_id))
                if (post and comment and
                        current_u.username == comment.created_by):
                    self.render(
                        'editcomment.html',
                        username=current_u.username,
                        post=post,
                        post_id=post_id,
                        comment=comment)
                else:
                    self.redirect('/blog/post_id')
            else:
                self.send_back()

        else:
            self.send_back()

    def post(self, post_id, comment_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                comment = Comment.get_by_id(int(comment_id))

                if post and comment:
                    content = self.request.get('content')
                    if content:
                        comment.content = content
                        comment.put()

                    self.redirect('/blog/%s' % post_id)
                else:
                    self.redirect('/blog/%s' % post_id)
            else:
                self.send_back()

        else:
            self.send_back()


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        cookie_val = self.request.cookies.get("user_id")
        if cookie_val:
            uid = check_secure_val(cookie_val)
            if uid:
                current_u = User.get_by_id(int(uid))
                post = Post.get_by_id(int(post_id))
                comment = Comment.get_by_id(int(comment_id))
                if (post and comment and
                        current_u.username == comment.created_by):
                    comment.delete()
                    self.redirect('/blog/%s' % post_id)
                else:
                    self.redirect('/blog')
            else:
                self.send_back()

        else:
            self.send_back()


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/register', Register),
    ('/login', Login),
    ('/welcome', Permalink),
    ('/blog', Blog),
    ('/blog/newpost', Newpost),
    ('/blog/([0-9]+)', Postpage),
    ('/blog/([0-9]+)/edit', Editpost),
    ('/blog/([0-9]+)/delete', Deletepost),
    ('/blog/logout', Logout),
    ('/blog/([0-9]+)/like', Likepost),
    ('/blog/([0-9]+)/dislike', Dislikepost),
    ('/blog/([0-9]+)/comment/add', CommentPage),
    ('/blog/([0-9]+)/comment/([0-9]+)/edit', EditComment),
    ('/blog/([0-9]+)/comment/([0-9]+)/delete', DeleteComment)
], debug=True)
