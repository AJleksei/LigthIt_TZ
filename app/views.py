#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime
import os
import re
import hashlib
import traceback
import urllib
import urllib2

from smtplib import SMTP_SSL
from jinja2 import Environment, FileSystemLoader
from webob import Request, Response

from models import *
#import settings

#from db import Database, User
#import Cookie
#import cgi
#from twisted.spread.pb import respond


def index(request):
    response = Response()
    user_data = get_user_data(request)
    page_content = {'user_data': user_data}
    response.text = templates.get_template('index.html').render(page_content)
    return response


def contacts(request):
    response = Response()
    user_data = get_user_data(request)
    data = {}
    errors = {}

    if request.POST:
        data['email'] = request.POST['email'].strip()
        data['message_subject'] = request.POST['message_subject'].strip()
        data['message'] = request.POST['message'].strip()

        if not validate_email(data['email']):
            errors['email'] = u'Введите корректный Емейл'

        if not data['message_subject']:
            errors['message_subject'] = u'Тема сообщения не может быть пустой'

        if len(data['message_subject']) > 2000:
            errors['message_subject'] = u'Тема сообщения не может быть больше 2000 символов'

        if not data['message']:
            errors['message'] = u'Сообщение не может быть пустым'

        if not data['message']:
            errors['message'] = u'Сообщение не может быть больше 50000 символов'

        if not errors:
            send_email(data['email'], data['message_subject'].encode('utf8'), data['message'].encode('utf8'))

    page_content = {
        'user_data': user_data,
        'errors': errors,
        'data': data
    }
    response.text = templates.get_template('contacts.html').render(page_content)
    return response


def login(request):
    response = Response()

    # Если пользователь залогинен, он не сможет попасть на страницу login
    user_auth = is_auth_user(request)
    if user_auth:
        return redirect_to_home(request)

    errors = {}
    data = {}

    if request.POST:
        login = data['login'] = request.POST['login'].strip()
        password = data['password'] = request.POST['password'].strip()

        if not validate_password(password):
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'

        if not validate_login(login):
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'

        if not errors:
            user_db = get_user_from_login(login)
            if user_db and user_db.password == md5(password):
                response = authorization(response, user_db)
                return redirect_to_home(request, response)
            else:
                errors['user'] = u"Неверное имя пользователя или пароль"

    page_content = {'errors': errors, 'data': data}

    response.text = templates.get_template('login.html').render(page_content)
    return response


def register(request):
    response = Response()

    # Если пользователь залогинелся, он не может попасть на эту страницу
    user_auth = is_auth_user(request)
    if user_auth:
        return redirect_to_home(request)

    errors = {}
    data = {}

    if request.POST:
        data['first_name'] = request.POST['first_name'].strip()
        data['last_name'] = request.POST['last_name'].strip()
        data['login'] = request.POST['login'].strip()
        data['password'] = request.POST['password'].strip()
        data['confirm_password'] = request.POST['confirm_password'].strip()
        data['email'] = request.POST['email'].strip()
        data['birth_date'] = request.POST['birth_date'].strip()
        data['mobile_phone'] = request.POST['mobile_phone'].strip()
        captcha = request.POST['g-recaptcha-response']

        if not validate_password(data['password']):
            errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'

        if not validate_password(data['confirm_password']):
            errors['confirm_password'] = u'Длина пароля должна быть от 6 до 16 символов'

        if data['password'] != data['confirm_password']:
            errors['confirm_password'] = u'Пароли не совпадают'

        if not validate_login(data['login']):
            errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'

        if not validate_first_last_name(data['first_name']):
            errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'

        if not validate_first_last_name(data['last_name']):
            errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'

        if not validate_email(data['email']):
            errors['email'] = u'Введите корректный Емейл'

        if not validate_birth_date(data['birth_date']):
            errors['birth_date'] = u'Введите корректную Дату'

        if not validate_phone(data['mobile_phone']):
            errors['mobile_phone'] = u'Введите корректный Мобильный телефон'

        if not submit(settings.RECAPTCHA_PRIVATE_KEY, captcha):
            errors['captcha'] = u"Captcha обязателен для заполнения"

        user_db = get_user_from_login(data['login'])
        if user_db:
            errors['login'] = u"Пользователь с таким логином уже существует"

        if not errors:
            # Запоминаем пароль, чтобы отправить его на емейл
            # Т.к. пароль сохраняется хешированый, а при сохранении может
            #  произойти ошибка, то отправляем сообщение, после сохранения
            # данных в БД
            password_hash = md5(data['password'])
            session_id = create_session_id()
            Users.create(last_name=data['last_name'], first_name=data['first_name'],
                         login=data['login'], password=password_hash,
                         email=data['email'], birth_date=data['birth_date'], mobile_phone=data['mobile_phone'],
                         session_id=session_id)

            # Формируем текст для отправки сообщения на email
            message = '''Регистрация прошла успешно.
                        Имя: {}
                        Фамилия: {}
                        Логин: {}
                        Пароль: {}
                        День рождения: {}
                        Мобильный телефон: {}''' \
                .format(data['last_name'], data['first_name'], data['login'], data['password'], data['password'],
                        data['mobile_phone'])
            subject = 'Регистрация прошла успешно!!!'
            # Отправляем сообщение, с регистрационными данными, на указаный email
            send_email(data['email'], subject, message)

            response.set_cookie('session_id', session_id)

            return redirect_to_home(request, response)

    page_content = {'errors': errors, 'data': data}
    response.text = templates.get_template('register.html').render(page_content)
    return response


def view_404(request):
    response = Response()
    user_data = get_user_data(request)
    page_content = {'user_data': user_data}
    response.status = '404 NOT FOUND'
    response.text = templates.get_template('404.html').render(page_content)
    return response


def view_500(request, error):
    response = Response()
    user_data = get_user_data(request)
    page_content = {
        'error_message': error.message,
        'error_info': traceback.format_exc(),
        'user_data': user_data
    }
    response.status = '500 INTERNAL SERVER ERROR'
    response.text = templates.get_template('500.html').render(page_content)
    return response


def delete_account(request):
    response = Response()

    user_auth = is_auth_user(request)
    # Удалить аккаут может только залогиненый пользователь
    if not user_auth:
        return redirect_to_home(request)

    # Удаляем пользователя из БД
    Users.delete().where(Users.session_id == user_auth.session_id)

    page_content = {}
    # Очищаем cookie
    response.delete_cookie('session_id')
    response.text = templates.get_template('delete_account.html').render(page_content)
    return response


def sign_out(request):

    user_auth = is_auth_user(request)
    # Не авторизованный пользователь не может попость на эту страницу
    if not user_auth:
        return redirect_to_home(request)

    response = Response()
    response.delete_cookie('session_id')

    page_content = {}
    response.text = templates.get_template('sign_out.html').render(page_content)
    return response


def field_validator(data):
    validate_fields = {
        ('first_name', validate_first_last_name, u'Длина Имени должна быть от 1 до 25 символов'),
        ('last_name', validate_first_last_name, u'Длина Фамилии должна быть от 1 до 25 символов'),
        ('login', validate_login, u'Длина Логина должна быть от 1 до 25 символов'),
        ('password', validate_password, u'Длина пароля должна быть от 6 до 16 символов'),
        ('old_password', validate_password, u'Длина пароля должна быть от 6 до 16 символов'),
        ('new_password', validate_password, u'Длина пароля должна быть от 6 до 16 символов'),
        ('new_confirm_password', validate_password, u'Длина пароля должна быть от 6 до 16 символов'),
        ('email', validate_email, u'Введите корректный Емейл'),
        ('birth_date', validate_birth_date, u'Введите корректную Дату'),
        ('mobile_phone', validate_phone, u'Введите корректный Мобильный телефон'),
    }

    errors = {}

    for field, validator, error in validate_fields:
        if data.__contains__(field):
            if not validator(data[field]):
                errors[field] = error

    return errors


def personal_account(request):
    response = Response()

    page_content = {}
    user_auth = is_auth_user(request)
    # Если пользователь не залогинен, отправляем его на главную страницу
    if not user_auth:
        return redirect_to_home(request)

    errors = {}
    data = {}

    # Если это метод POST
    if request.POST:
        # Если в форме есть поле password
        if request.POST.__contains__('old_password'):
            data['old_password'] = request.POST['old_password'].strip()
            data['new_password'] = request.POST['new_password'].strip()
            data['new_confirm_password'] = request.POST['new_confirm_password'].strip()

            errors = field_validator(data)

            #if not validate_password(data['password']):
            #   errors['password'] = u'Длина пароля должна быть от 6 до 16 символов'

            # Если ошибок нет
            if not errors:
                session_id = request.cookies['session_id']
                user_db = get_user_from_session_id(session_id)

                # Изменяем пароль в БД
                user_db.password = md5(data['password'])
                user_db.session_id = create_session_id()
                user_db.save()
                # Обновляем cookie
                response.set_cookie('session_id', user_db.session_id)
        elif request.POST.__contains__('photo'):
            if request.POST['photo'].file:
                photo = request.POST['photo'].file.read()
                #import imghdr
                #imghdr.what(photo)
                # Ищем расширение файла
                #start = request.POST['photo'].filename.find('.')
                #end = len(request.POST['photo'].filename)
                #os.path.name
                extension = os.path.splitext(request.POST['photo'])[1].replace('.', '')

                # Получаем расширение файла
                #filename = request.POST['photo'].filename[start:end]

                # В название картинки пишем id юзера, чтобы не было конфликтов
                # Если пользователь загрузит еще аватарку, то старая перезапишется
                filename = os.path.join('media/', user_auth.login + extension)
                f = open(filename, 'wb')
                f.write(photo)
                f.close()

                user_auth.photo = filename
                user_auth.save()
            else:
                errors['photo'] = u'Файл не выбран'
        else:
            data['first_name'] = request.POST['first_name'].strip()
            data['last_name'] = request.POST['last_name'].strip()
            data['login'] = request.POST['login'].strip()
            data['email'] = request.POST['email'].strip()
            data['birth_date'] = request.POST['birth_date'].strip()
            data['mobile_phone'] = request.POST['mobile_phone'].strip()

            if not validate_first_last_name(data['first_name']):
                errors['first_name'] = u'Длина Имени должна быть от 1 до 25 символов'

            if not validate_first_last_name(data['last_name']):
                errors['last_name'] = u'Длина Фамилии должна быть от 1 до 25 символов'

            if not validate_email(data['email']):
                errors['email'] = u'Введите корректный Емейл'

            if not validate_birth_date(data['birth_date']):
                errors['birth_date'] = u'Введите корректную дату'

            if not validate_phone(data['mobile_phone']):
                errors['mobile_phone'] = u'Введите корректный Мобильный телефон'

            if not validate_login(data['login']):
                errors['login'] = u'Длина Логина должна быть от 1 до 25 символов'

            # Если ошибок нет
            if not errors:
                session_id = request.cookies['session_id']
                user_db = get_user_from_session_id(session_id)
                if user_db:
                    user_check_login = get_user_from_login(data['login'])
                    if user_check_login and user_check_login.session_id != user_db.session_id:
                        errors['login'] = u"Пользователь с таким логином уже существует"

                    else:
                        # Сохраняем изменения в БД
                        user_db.login = data['login']
                        user_db.first_name = data['first_name']
                        user_db.last_name = data['last_name']
                        user_db.email = data['email']
                        user_db.birth_date = data['birth_date']
                        user_db.mobile_phone = data['mobile_phone']
                        user_db.save()

    elif request.method == 'GET' or request.POST and\
            request.POST.__contains__('password') or request.POST.__contains__('photo'):
        # Если это GET запрос или POST с изменением пароля
        session_id = request.cookies['session_id']
        user_db = get_user_from_session_id(session_id)
        if user_db:
            data['first_name'] = user_db.first_name
            data['last_name'] = user_db.last_name
            data['login'] = user_db.login
            data['email'] = user_db.email
            data['birth_date'] = user_db.birth_date
            data['mobile_phone'] = user_db.mobile_phone

    user_data = get_user_data(request)
    page_content['user_data'] = user_data
    page_content['data'] = data
    page_content['errors'] = errors
    response.text = templates.get_template('personal_account.html').render(page_content)
    return response


def static(request):
    response = Response()

    extension = os.path.splitext(request.path_url)[1].replace('.', '')
    mime = settings.mime_types.get(extension, 'text/html')

    file_path = os.path.join(settings.STATIC,
                             request.path_info.replace('/static/', ''))

    try:
        file = open(file_path, 'rb')
        response.body = file.read()
    except Exception:
        try:
            file_path = os.path.join(settings.MEDIA,
                                 request.path_info.replace('/media/', ''))
            file = open(file_path, 'rb')
            response.body = file.read()
        except Exception:
            return view_404(request)
        else:
            response.content_type = mime
    else:
        response.content_type = mime
    return response


def load_avatar(request):
    response = Response()

    user_auth = is_auth_user(request)
    if not user_auth:
        return redirect_to_home(request)

    errors = {}
    data = {}

    if request.POST:
        photo = request.POST['photo'].file.read()
        # Ищем расширение файла
        start = request.POST['photo'].filename.find('.')
        end = len(request.POST['photo'].filename)
        os.path.name

        # Получаем расширение файла
        filename = request.POST['photo'].filename[start:end]

        # В название картинки пишем id юзера, чтобы не было конфликтов
        # Если пользователь загрузит еще аватарку, то старая перезапишется
        target = os.path.join('media/', user_auth.login + filename)
        f = open(target, 'wb')
        f.write(photo)
        f.close()

        user_auth.photo = target
        user_auth.save()
    if request.GET:
        """
        # Если это GET запрос
        database = Database()
        user_id = None
        try:
            user_id = Cookie.SimpleCookie(environ.get("HTTP_COOKIE", ""))[
                "user_id"].value
        except:
            user_id = None
        user_db = database.get_user_from_id(user_id)
        if user_db:
            data['first_name'] = user_db.firstName
            data['last_name'] = user_db.lastName
            data['login'] = user_db.login
            data['email'] = user_db.email
            data['birthDate'] = user_db.birthDate
            data['mobilePhone'] = user_db.mobilePhone
        """

    template = templates.get_template('personal_account.html')

    args = {'errors': errors, 'data': data}
    #return status, headers, template, args,
    return response


def get_stylesheets(environ):
    status = '200 OK'
    headers = [
        ('Content-type', 'text/css; charset=utf-8'),
    ]
    stylesheets = Environment(
        loader=FileSystemLoader(settings.BASE_PATH + '/stylesheets'))
    template = stylesheets.get_template('stylesheet.css')
    args = {}
    return status, headers, template, args,


md5 = lambda x: hashlib.md5(x).hexdigest()

templates = Environment(loader=FileSystemLoader(settings.BASE_PATH + '/templates'))

re_first_last_name = re.compile('[a-zA-Zа-яА-Я]{1,25}')
re_login = re.compile('[a-zA-Z0-9]{1,25}')
re_password = re.compile('[a-zA-Z0-9]{6,16}')
re_email = re.compile('[^@]+@[^@]+\.[^@]+')
re_phone = re.compile('[0-9]{3}-[0-9]{7}')
re_birth_date = re.compile('[0-9]{4}-[0-9]{2}-[0-9]{2}')


def validate_first_last_name(first_last_name):
    if not re_first_last_name.search(first_last_name):
        return False
    return True


def validate_login(login):
    if not re_login.search(login):
        return False
    return True


def validate_password(password):
    if not re_password.search(password):
        return False
    return True


def validate_email(email):
    if not re_email.search(email):
        return False
    return True


def validate_phone(phone):
    if not re_phone.search(phone):
        return False
    return True


def validate_birth_date(birth_date):
    if not re_birth_date.search(birth_date):
        return False
    try:
        import datetime
        datetime.datetime.strptime(birth_date, '%Y-%m-%d').date()
    except Exception:
        return False
    return True


# Редирект на домашнюю страницу
def redirect_to_home(request, response=None):
    if not response:
        response = Response()
    response.location = request.host_url
    response.status = '301 Moved'
    return response


# Генерируем id сессии
def create_session_id():
    return hashlib.sha224(os.urandom(56)).hexdigest()


# Записываем id юзера из базы в cookie
def authorization(response, user):
    response.set_cookie('session_id', user.session_id)
    return response


# Проверка авторизован ли пользователь
# Если в cookie тот же session_id что и в базе, значит пользователь авторизован
def is_auth_user(request):
    try:
        session_id = request.cookies['session_id']
        user = get_user_from_session_id(session_id)
        return user
    except Exception:
        return None


# Метод для отправки сообщений на емейл
def send_email(to_addr, subject, message):
    # Формируем сообщение
    msg = "From: {}\nTo: {}\nSubject: {}\n\n{}".format(
        settings.FROM_EMAIL, to_addr,subject, message)

    # Отправляем сообщение
    smtp = SMTP_SSL()
    smtp.connect(settings.SMTP)
    smtp.login(settings.FROM_EMAIL_LOGIN, settings.FROM_EMAIL_PASSWORD)
    smtp.sendmail(settings.FROM_EMAIL, to_addr, msg)
    smtp.quit()


# Проверка валидности введеной капчи
def submit(secret, response):
    if not response or not secret:
        return False

    def encode_if_necessary(s):
        if isinstance(s, unicode):
            return s.encode('utf-8')
        return s

    params = urllib.urlencode({
        'secret': encode_if_necessary(secret),
        'response': encode_if_necessary(response),
    })

    request = urllib2.Request(
        url="https://www.google.com/recaptcha/api/siteverify",
        data=params,
        headers={
            "Content-type": "application/x-www-form-urlencoded",
            "User-agent": "reCAPTCHA Python"
        }
    )

    httpresp = urllib2.urlopen(request)

    return_values = httpresp.read().splitlines()
    httpresp.close()

    return_code = return_values[1]

    if return_code.find('true'):
        return True
    else:
        return False


def get_user_data(request):
    if request.cookies.__contains__('session_id'):
        session_id = request.cookies['session_id']
        user = get_user_from_session_id(session_id)
        user_data = {
            'name': '{} {}.'.format(user.first_name, user.last_name[0]),
            'image': user.photo or '/static/img/default.png'
        }
        return user_data
    return None

"""
#Проверка капчи
def captcha_check(request):
    #return True
    secret = settings.RECAPTCHA_PRIVATE_KEY
    response = request.POST['g-recaptcha-response']
    remoteip = get_client_ip(request)
    if response == '':
        return False
    else:
        #Запрос в гугл за результатом
        result = get_captcha_result(secret, response, remoteip)
        try:
            #парсим ответ
            struct_result = json.loads(result)
        except Exception:
            return False
        else:
            print struct_result
            #проверяем
            if struct_result['success'] == True:
                return True
            else:
                return False

#IP юзера
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0] #[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

#Формируем и посылаем запрос к гуглу
def get_captcha_result(secret, response, remoteip):
    url = 'https://www.google.com/recaptcha/api/siteverify?'
    if settings.PROXY_ON:
        opener = connect_proxy()
    else:
        opener = urllib2.build_opener()
    data = [
        ('secret', secret),
        ('response', response),
        ('remoteip', remoteip)
    ]
    encode_data = urllib.urlencode(data)
    request = urllib2.Request(url + encode_data)
    try:
        result = opener.open(request)
    except Exception, e:
        return e
    else:
        success = result.read()
        return success
"""