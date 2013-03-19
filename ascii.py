#!/usr/bin/env python

import logging
import webapp2
import cgi
import re
import sys
import os
import jinja2
import urllib2
import logging
from xml.dom import minidom
from string import letters

from google.appengine.api import memcache
from google.appengine.ext import db

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

def render_str(template, **params):
		t = jinja_environment.get_template(template)
		return t.render(params)

class BaseHandler(webapp2.RequestHandler):
	def render(self, template, **kw):
		self.response.out.write(self.render_str(template, **kw))

	def render_str(self, template, **params):
		t = jinja_environment.get_template(template)
		return t.render(params)

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
	#ip = "4.2.2.2"
	#ip = "23.24.209.141"
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return
	if content:
		#parse xml and find the coordinates
		d = minidom.parseString(content)
		coords = d.getElementsByTagName("gml:coordinates")
		if coords and coords[0].childNodes[0].nodeValue:
			lon, lat = coords[0].childNodes[0].nodeValue.split(',')
			return db.GeoPt(lat, lon)

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
	markers = '&'.join('markers=%s,%s' % (p.lat, p.lon) for p in points)
	return GMAPS_URL + markers

class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords = db.GeoPtProperty()

def top_arts(update = False):
	key  = 'top'
	arts = memcache.get(key)
	if arts is None or update:
		logging.error('DB QUERY')
		arts = db.GqlQuery("SELECT * "
						   "FROM Art "
						   "ORDER BY created DESC "
						   "LIMIT 10")
		arts = list(arts)
		memcache.set(key, arts)
	return arts

class AsciiHandler(BaseHandler):
	def render_front(self, title="", art="", error=""):
		arts = top_arts()

		#find which arts have coords
		points = filter(None, (a.coords for a in arts))

		#if we have any arts with coords, make an image url
		img_url = None
		if points:
			img_url = gmaps_img(points)
		
		#display the image url

		self.render('front.html', title=title, art=art, error=error, arts=arts,
					img_url = img_url)

	def get(self):
		#self.write(self.request.remote_addr)
		#self.write(repr(get_coords(self.request.remote_addr)))
		self.render_front()

	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")

		if title and art and not self.check_if_dick(art):
			 a = Art(title = title, art = art)

			 #look up user's coordinates from their IP
			 coords = get_coords(self.request.remote_addr)
			 #if we have coordinates, add them to the Art
			 if coords:
			 	a.coords = coords

			 a.put()
			 #rerun the query and update CACHE
			 top_arts(True)

			 self.redirect("/ascii")
		else:
			error = "we need both a title and some art!"
			self.render_front(title, art, error)

	def check_if_dick(self, nice_try):
		regex = re.compile(r'8=+>~*')
		return regex.match(nice_try)

routes = [('/ascii', AsciiHandler)]
app = webapp2.WSGIApplication(routes=routes, debug=True)
