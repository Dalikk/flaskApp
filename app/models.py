import app
from flask import current_app
from . import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from authlib.jose import JsonWebSignature
import json


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permission(self):
        self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE, Permission.MODERATE],
            'Administrator': [Permission.FOLLOW, Permission.COMMENT,
                              Permission.WRITE, Permission.MODERATE, Permission.ADMIN],
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permission()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self):
        jws = JsonWebSignature()
        protected = {'alg': 'HS256'}
        payload = self.id
        secret = current_app.config['SECRET_KEY']
        return jws.serialize_compact(protected, payload, secret).decode('utf-8')

    def confirm(self, token):
        jws = JsonWebSignature()
        secret = current_app.config['SECRET_KEY']
        try:
            data = jws.deserialize_compact(token.encode('utf-8'), secret)
        except:
            return False
        if int(data['payload']) != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self):
        jws = JsonWebSignature()
        protected = {'alg': 'HS256'}
        payload = self.id
        secret = current_app.config['SECRET_KEY']
        return jws.serialize_compact(protected, payload, secret).decode('utf-8')

    @staticmethod
    def reset_password(token, new_password):
        jws = JsonWebSignature()
        secret = current_app.config['SECRET_KEY']
        try:
            data = jws.deserialize_compact(token.encode('utf-8'), secret)
        except:
            return False
        user = User.query.get(int(data['payload']))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email):
        jws = JsonWebSignature()
        secret = current_app.config['SECRET_KEY']
        protected = {'alg': 'HS256'}
        payload = str({'change_email': self.id, 'new_email': new_email}).encode('utf-8')
        token = jws.serialize_compact(protected, payload, secret)
        return token

    def change_email(self, token):
        jws = JsonWebSignature()
        secret = current_app.config['SECRET_KEY']
        try:
            data = jws.deserialize_compact(token, secret)
        except:
            return False
        payload_string = data['payload'].decode('utf-8').replace("'", "\"")
        payload_dict = json.loads(payload_string)
        if payload_dict['change_email'] != self.id:
            return False
        new_email = payload_dict['new_email']
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        db.session.add(self)
        return True

    def __repr__(self):
        return '<User %r>' % self.username
