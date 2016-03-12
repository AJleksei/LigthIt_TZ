import re
import views
import settings


# compile url regexp
def url(url, view):
    return (re.compile(url, re.IGNORECASE), view,)

urls = [
    url(r'^/$', views.index),
    url(r'^/index$', views.index),
    url(r'^/contacts$', views.contacts),
    url(r'^/personal_account$', views.personal_account),
    url(r'^/login$', views.login),
    url(r'^/sign_out$', views.sign_out),
    url(r'^/register$', views.register),
    url(r'^/delete_account$', views.delete_account),
    url(r'^/static/[\w/.-]+\.(jpe?g)?(png)?(css)?(js)?(gif)?(ttf)?$', views.static),
    url(r'^/favicon.ico$', views.static),
]