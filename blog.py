#!/usr/bin/env python

import webapp2
import cgi
import re
import os
import jinja2
import urllib2
from xml.dom import minidom
from string import letters
import hashlib
import hmac
import logging
import json
from datetime import datetime, time
from google.appengine.api import memcache
from google.appengine.ext import db

SECRET = '' #redacted for security

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def render_str(template, **params):
	t = jinja_environment.get_template(template)
	return t.render(params)

class BaseHandler(webapp2.RequestHandler):
	def render(self, template, **kw):
		self.response.out.write(render_str(template, **kw))

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		username = self.request.cookies.get('user')
		user_check = check_secure_val(username)
		if user_check:
			self.response.out.write("Welcome, "+user_check)
		else:
			self.redirect('/blog/signup')

class SignupHandler(BaseHandler):
	def write_signup(self, username="", email="", username_error="",
					 password_error="", verify_error="", email_error=""):
		self.response.out.write(signup % {"username": escape_html(username), 
										  "email": escape_html(email),
										  "username_error": username_error,
										  "password_error": password_error,
										  "verify_error": verify_error,
										  "email_error": email_error})
	
	def get(self):
		self.render('signup.html')

	def post(self):
		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_verify   = self.request.get('verify')
		user_email    = self.request.get('email')

		is_username_valid = valid_username(user_username)
		is_password_valid = valid_password(user_password)
		if (user_password==user_verify):
			is_verify_valid = True
		else:
			is_verify_valid = False
		is_email_valid    = valid_email(user_email)

		if (is_username_valid and is_password_valid
			and is_verify_valid and is_email_valid):
			self.redirect("/blog/welcome?username="+user_username)
		else:
			params = {'username': user_username,
				  	  'email': user_email}
			if not is_username_valid:
				params['username_error'] = "That's not a valid username."
			if not is_password_valid:
				params['password_error'] = "That wasn't a valid password."
			if not is_verify_valid:
				params['verify_error'] = "Your passwords didn't match."
			if not is_email_valid:
				params['email_error'] = "That's not a valid email."
			self.render('signup.html', **params)

class Post(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		self._id = self.key().id()
		return render_str('post.html', p=self)

def front_page(update=False):
	posts_key = 'blog_front_page'
	time_key = 'time'
	posts = memcache.get(posts_key)
	if posts is None or update:
		logging.info("DB QUERY")
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 0, 10")
		posts = list(posts)
		time = datetime.now()
		memcache.set(posts_key, posts)
		memcache.set(time_key, time)
	else:
		posts = memcache.get(posts_key)
		time = memcache.get(time_key)
	return time, posts

class BlogHandler(BaseHandler):
	def get(self):
		#get posts from db/memcache
		time, posts_query = front_page()
		posts = []
		for post in posts_query:
			post._id = post.key().id()
			posts.append(post)
		seconds = (datetime.now() - time).seconds
		#logging.error("SECONDS: "+str(seconds))
		self.render('block_blog.html', posts=posts)
		self.write('"Database Queried '+str(seconds)+' seconds ago"')

class NewPostHandler(BaseHandler):
	def render_new_post_page(self, title="", content="", error=""):
		self.render('new_post.html', title=title, content=content, error=error)

	def get(self):
		self.render_new_post_page()

	def post(self):
		title = self.request.get("subject")
		content = self.request.get("content")

		if title and content:
			p = Post(title=title, content=content)
			p_key = p.put()
			front_page(True)
			self.redirect("/blog/%d" % p_key.id())
		else:
			error = "please input a title and content"
			self.render_new_post_page(title, content, error)

class FlushHandler(BaseHandler):
	def get(self):
		memcache.flush_all()
		self.redirect('/blog')

def permalink(id):
	time_key = str(id)+' post_time'
	id_key = str(id)
	post = memcache.get(id_key)
	if post is None:
		post = Post.get_by_id(int(id))
		time = datetime.now()
		memcache.set(id_key, post)
		memcache.set(time_key, time)
	else:
		post = memcache.get(id_key)
		time = memcache.get(time_key)
	return time, post

class PermalinkHandler(BaseHandler):
	def get(self, post_id):
		time, s = permalink(post_id)
		s._id = post_id
		if not s:
			self.error(404)
			return

		self.render('block_blog.html', posts=[s])
		seconds = (datetime.now() - time).seconds
		self.write('"Database Queried '+str(seconds)+' seconds ago"')

class BlogJsonHandler(BaseHandler):
	def get(self):
		#get posts from db
		posts_query = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 0, 10")
		posts = []
		for post in posts_query:
			post._id = post.key().id()
			posts.append(post)
		self.response.headers['Content-Type']  = 'application/json; charset=UTF-8'
		to_dump = []
		for s in posts:
			to_dump.append({'content': s.content,
							'title': s.title,
							'created': s.created.strftime('%c'),
							'modified': s.last_modified.strftime('%c')})
		self.response.headers['Content-Type']  = 'application/json; charset=UTF-8'
		self.write(json.dumps(to_dump))

class PostJsonHandler(BaseHandler):
	def get(self, post_id):
		s = Post.get_by_id(int(post_id))
		s._id = post_id
		if not s:
			self.error(404)
			return
		to_dump = [{'content': s.content,
					'title': s.title,
					'created': s.created.strftime('%c'),
					'modified': s.last_modified.strftime('%c')}]
		self.response.headers['Content-Type']  = 'application/json; charset=UTF-8'
		self.write(json.dumps(to_dump))

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class LoginHandler(BaseHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_query = db.GqlQuery("SELECT * FROM User")
		users = []
		passwords = []
		for user in user_query:
			user._id = user.key().id()
			users.append(user.username)
			passwords.append(user.password)

		if user_username in users:
			if hash_str(user_password)==passwords[users.index(user_username)]:
				new_cookie_val = make_secure_val(user_username)
				str_new_cookie_val = str(new_cookie_val)
				self.response.headers.add_header('Set-Cookie', 'user='+str_new_cookie_val+'; Path=/')
				self.redirect("/blog/welcome")
				return

		#else
		params = {}
		params['error'] = "Invalid login"
		self.render('login.html', **params)
  
class LogoutHandler(BaseHandler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user=;Path=/')
		self.redirect("/blog/signup")

class SignupHandler(BaseHandler):	
	def get(self):
		self.render('signup.html')

	def post(self):
		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_verify   = self.request.get('verify')
		user_email    = self.request.get('email')

		is_username_valid = valid_username(user_username)
		is_password_valid = valid_password(user_password)
		if (user_password==user_verify):
			is_verify_valid = True
		else:
			is_verify_valid = False
		is_email_valid    = valid_email(user_email)

		if (is_username_valid and is_password_valid
			and is_verify_valid and is_email_valid):
			#check if user already in database
			#get users from db
			user_query = db.GqlQuery("SELECT * FROM User")
			users = []
			for user in user_query:
				user._id = user.key().id()
				users.append(user.username)

			if user_username in users:
				params = {}
				params['username_error'] = "That user alreay exists"
				self.render('signup.html', **params)
				return
			else:
				#else add user
				u = User(username=user_username, password=hash_str(user_password))
				u.put()
				new_cookie_val = make_secure_val(user_username)
				str_new_cookie_val = str(new_cookie_val)
				self.response.headers.add_header('Set-Cookie', 'user='+str_new_cookie_val+'; Path=/')
				self.redirect("/blog/welcome")	

		else:
			params = {'username': user_username,
				  	  'email': user_email}
			if not is_username_valid:
				params['username_error'] = "That's not a valid username."
			if not is_password_valid:
				params['password_error'] = "That wasn't a valid password."
			if not is_verify_valid:
				params['verify_error'] = "Your passwords didn't match."
			if not is_email_valid:
				params['email_error'] = "That's not a valid email."
			self.render('signup.html', **params)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

def escape_html(s):
	return cgi.escape(s, quote = True)

routes = [('/blog/signup', SignupHandler),
		  ('/blog/welcome', WelcomeHandler),
		  ('/blog/?', BlogHandler),
		  ('/blog/newpost', NewPostHandler),
		  ('/blog/(\d+)', PermalinkHandler),
		  ('/blog/login', LoginHandler),
		  ('/blog/logout', LogoutHandler),
		  ('/blog/.json', BlogJsonHandler),
		  ('/blog/(\d+).json', PostJsonHandler),
		  ('/blog/flush', FlushHandler)]
app = webapp2.WSGIApplication(routes=routes, debug=True)
