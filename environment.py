#!/usr/bin/env python
# -*- coding: utf-8 -*-

from wsgiref.simple_server import make_server


def index(environ):
    body = 'Request type: {}'.format(environ['QUERY_STRING'])
    status = '200 OK'
    headers = [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(body)))
    ]
    return (status, headers, body,)


def contacts(environ):
    body = 'Request type: {}'.format(environ['PATH_INFO'])
    status = '200 OK'
    headers = [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(body)))
    ]
    return (status, headers, body,)


def personal_account(environ):
    body = 'Request type: {}'.format(environ['PATH_INFO'])
    status = '200 OK'
    headers = [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(body)))
    ]
    return (status, headers, body,)


def sign_in(environ):
    body = 'Request type: {}'.format(environ['PATH_INFO'])
    status = '200 OK'
    headers = [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(body)))
    ]
    return (status, headers, body,)


def base(environ):
    body = '\n'.join(['{}: {}'.format(key, value) for key, value in sorted(environ.items())])
    status = '200 OK'
    headers = [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(body)))
    ]
    return (status, headers, body,)


def view_404():
    status = '404 NOT FOUND'
    body = '<h1>This page not found<h1>'
    headers = [
        ('Content-Type', 'text/html'),
        ('Content-Length', str(len(body)))
    ]
    return (status, headers, body,)


def view_500(error):
    status = '500 INTERNAL SERVER ERROR'
    body = '<h2>INTERNAL SERVER ERROR</h2>\n{}'.format(error.message)
    headers = [
        ('Content-Type', 'text/html'),
        ('Content-Length', str(len(body)))
    ]
    return (status, headers, body,)


def get_view(environ):
    # Определяем, какую страницу нужно показать клиенту

    # Определяем, по какаму адресу перешел клиент
    request_url = environ['PATH_INFO']

    urls = {
        '/': index,
        '/contacts': contacts,
        '/personal_account': personal_account,
        '/sign_in': sign_in,
        '/base': base,
    }

    try:
        return urls[request_url]
    except KeyError:
        return view_404


def application(environ, start_response):
    view = get_view(environ)
    try:
        status, headers, body = view(environ)
    except Exception, error:
        status, headers, body = view_500(error)
    start_response(status, headers)
    return body


httpd = make_server('localhost', 8051, application)

# Now it is serve_forever() in instead of handle_request()
httpd.serve_forever()