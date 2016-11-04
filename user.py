import hashlib
import random
import string

from google.appengine.ext import db

# salt and password hashing
# user stuff


def make_salt(length=5):
    str = ""
    for i in range(0, 5):
        str += random.choice(string.ascii_letters)
    return str


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, password, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, password, salt)


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_name(cls, username):
        u = User.all().filter('username =', username).get()
        return u

    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username)
        if u and valid_pw(username, password, u.pw_hash):
            return u
