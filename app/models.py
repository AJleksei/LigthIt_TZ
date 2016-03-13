# -*- coding: utf-8 -*-
from peewee import *
import settings

#db = SqliteDatabase('people.db')

class Users(Model):
    # id = IntegerField(primary_key=True)
    login = CharField(max_length=50, unique=True)
    password = CharField(max_length=56)
    email = CharField(max_length=50)
    first_name = CharField(max_length=50)
    last_name = CharField(max_length=50)
    birth_date = DateField()
    mobile_phone = CharField(max_length=20)
    photo = CharField(null=True)
    session_id = CharField(max_length=56)

    class Meta:
        database = settings.db  # This model uses the "test.db" database.


def get_user_from_session_id(session_id):
    try:
        user = Users.get(Users.session_id == session_id)
        return user
    except Exception:
        return None


def get_user_from_login(login):
    try:
        user = Users.get(Users.login == login)
        return user
    except Exception:
        return None


"""
def get_user_from_login(self, login):
        user = None
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            # Получаем пользователя по логину
            for user_db in c.execute(
                                    'SELECT DISTINCT * FROM Users WHERE login '
                                    'LIKE "' + login + '"'):
                user = User(user_db[0], user_db[1], user_db[2], user_db[3],
                            user_db[4], user_db[5], user_db[6], user_db[7],
                            user_db[8])
        finally:
            conn.close()
        return user







def get_all_users(self):
        users = []
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            # Получаем пользователя по логину
            for user_db in c.execute('SELECT DISTINCT * FROM Users'):
                user = User(user_db[0], user_db[1], user_db[2], user_db[3],
                            user_db[4], user_db[5], user_db[6], user_db[7],
                            user_db[8])
                users.append(user)
        finally:
            conn.close()
        return users





def add_user(self, user):
        user_new = None
        try:
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            user_new = c.execute(
                "INSERT INTO Users (id, lastName, firstName, login, password, email, birthDate,"
                "mobilePhone, session_id) VALUES(NULL, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user.lastName, user.firstName, user.login,
                 user.password, user.email, user.birthDate, user.mobilePhone,
                 user.session_id))
            conn.commit()
        finally:
            # Закрываем соединение с БД в любом случае
            conn.close()
        return user_new

    def edit_user(self, user):
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            user = c.execute(
                'UPDATE Users SET lastName = ?, firstName = ?, login = ?, password = ?, email = ?, '
                'birthDate = ?, mobilePhone = ?, session_id = ? WHERE id= ? ',
                (user.lastName, user.firstName, user.login, user.password,
                 user.email, user.birthDate, user.mobilePhone,
                 user.session_id, user.id))
            conn.commit()
        finally:
            conn.close()
        return user

    def delete_user_from_id(self, user_id):
        try:
            # Подключаемся к БД
            conn = sqlite3.connect('TZ.db')
            c = conn.cursor()

            c.execute('DELETE FROM Users WHERE id= ? ', user_id)
            conn.commit()
        finally:
            conn.close()

"""




def create_tables():
    settings.db.connect()
    settings.db.create_tables([Users], True)

    """
        self.id = id
        self.lastName = lastName
        self.firstName = firstName
        self.login = login
        self.password = password
        self.email = email
        self.birthDate = birthDate
        self.mobilePhone = mobilePhone
        self.session_id = session_id




            first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    login = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=56)
    mail = models.CharField(max_length=50)
    birth_date = models.DateField()
    phone = models.BigIntegerField()
    photo = models.FileField(upload_to='avatars', null=True)
    my_session_id = models.CharField(max_length=56)


       """

    """
    birthday = DateField()
    is_relative = BooleanField()
    """
