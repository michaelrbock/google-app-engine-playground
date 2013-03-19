#!/usr/bin/env python
#
# Unit ___

import webapp2
import cgi
import re
import os
import jinja2

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

def render_str(template, **params):
	t = jinja_environment.get_template(template)
	return t.render(params)

class BaseHandler(webapp2.RequestHandler):
	def render(self, template, **kw):
		self.response.out.write(render_str(template, **kw))

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

class MainPage(BaseHandler):
	def get(self):
		self.render('main_page.html')

routes = [('/', MainPage)]
app = webapp2.WSGIApplication(routes=routes, debug=True)
