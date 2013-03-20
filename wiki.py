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

jinja_environment = jinja2.Environment(autoescape=False,
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

class WikiPage(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

def get_title(page):
	if page=='':
		return '/'
	return page

class EditPageHandler(BaseHandler):
	def get(self, page=''):
		title = get_title(page)

		#check if page in db
		q = db.Query(WikiPage)
		q.filter('title =', title)
		wiki_page = q.get()

		params = {}
		params['title'] = title

		if wiki_page:
			params['content'] = wiki_page.content

		#check if user is signed in, else redirect
		if not self.request.cookies.get('user'):
			if wiki_page:
				self.redirect('/wiki/'+title[1:])
				return
			else:
				self.redirect('/wiki/login')
				return
		elif self.request.cookies.get('user'):
			if not check_secure_val(self.request.cookies.get('user')):
				if wiki_page:
					self.redirect('/wiki/'+title[1:])
					return
				else:
					self.redirect('/wiki/logout')
					return
			else:
				params['user'] = check_secure_val(self.request.cookies.get('user'))
				self.render('edit.html', **params)

	def post(self, page=''):
		title = get_title(page)
		content = self.request.get('content')

		#check if page in db
		q = db.Query(WikiPage)
		q.filter('title =', title)
		wiki_page = q.get()

		if content:
			#delete old if exists
			if wiki_page:
				wiki_page.delete()

			w = WikiPage(title=title, content=content)
			w.put()
			self.redirect('/wiki/'+title[1:])
		else:
			self.redirect('/wiki/_edit/'+title[1:])

class WikiPageHandler(BaseHandler):
	def get(self, page=''):
		title = get_title(page)

		#check if page in db
		q = db.Query(WikiPage)
		q.filter('title =', title)
		wiki_page = q.get()

		params = {}
		params['title'] = title

		if wiki_page:
			params['content'] = wiki_page.content
			if self.request.cookies.get('user'):
				if check_secure_val(self.request.cookies.get('user')):
					params['user'] = check_secure_val(self.request.cookies.get('user'))
			self.render('base_wiki.html', **params)
		else:
			self.redirect('/wiki/_edit/'+title[1:])

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class LoginHandler(BaseHandler):
	def get(self):
		next_url = self.request.headers.get('referer', '/wiki')
		self.render('login.html', next_url = next_url)

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

		#redirect stuff
		next_url = str(self.request.get('next_url'))
		if not next_url or next_url.startswith('/wiki/login'):
			next_url = '/wiki'

		if user_username in users:
			if hash_str(user_password)==passwords[users.index(user_username)]:
				new_cookie_val = make_secure_val(user_username)
				str_new_cookie_val = str(new_cookie_val)
				self.response.headers.add_header('Set-Cookie', 'user='+str_new_cookie_val+'; Path=/')
				self.redirect(next_url)
				return

		#else
		params = {}
		params['error'] = "Invalid login"
		self.render('login.html', **params)

class LogoutHandler(BaseHandler):
	def get(self):
		next_url = self.request.headers.get('referer', '/wiki')
		self.response.headers.add_header('Set-Cookie', 'user=;Path=/')
		self.redirect(next_url)

class SignupHandler(BaseHandler):
	def get(self):
		next_url = self.request.headers.get('referer', '/')
		self.render('signup.html', next_url = next_url)

	def post(self):
		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_verify   = self.request.get('verify')
		user_email    = self.request.get('email')

		#redirect stuff
		next_url = str(self.request.get('next_url'))
		if not next_url or next_url.startswith('/wiki/login'):
			next_url = '/wiki'

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
				self.redirect(next_url)

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

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

routes = [('/wiki/signup', SignupHandler),
          ('/wiki/login', LoginHandler),
          ('/wiki/logout', LogoutHandler),
          ('/wiki/_edit'+PAGE_RE, EditPageHandler),
          ('/wiki'+PAGE_RE, WikiPageHandler),
          ('/wiki/?', WikiPageHandler)]
app = webapp2.WSGIApplication(routes=routes, debug=True)
