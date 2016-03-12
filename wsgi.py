# -*- coding: utf-8 -*-
import settings
import db
import imp
from views import view_404, view_500
from webob import Request, Response


def application(environ, start_response):
    request = Request(environ)
    view = get_view1(environ)

    response = view(environ)

    return response(environ, start_response)


def get_view1(environ):
    urls = imp.load_source('urls', settings.URLS).urls
    request_url = environ['PATH_INFO']
    for url in urls:
        if url[0].match(request_url):
            return url[1]
    return view_404


def get_view(request):
    urls = imp.load_source('urls', settings.URLS).urls
    request_url = request.path_info
    for url in urls:
        if url[0].match(request_url):
            return url[1]
    return view_404