import app
from flask import current_app
from . import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from authlib.jose import JsonWebSignature


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name


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

    def __repr__(self):
        return '<User %r>' % self.username
