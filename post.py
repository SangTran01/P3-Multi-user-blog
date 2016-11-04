from google.appengine.ext import db


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.StringProperty(required=True)
    users_liked = db.StringListProperty(default=None)
    users_disliked = db.StringListProperty(default=None)
    likes = db.IntegerProperty(default=0)
    comments = db.ListProperty(db.Key, default=None)
