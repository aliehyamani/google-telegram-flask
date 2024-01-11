from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask import Flask,session,abort
from os import path
import os

db = SQLAlchemy()
DB_NAME = "data.db"

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'fr8551rfesfeve sedfsef'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    db.init_app(app)

    from Routing import R

    app.register_blueprint(R, url_prefix='/')

    from models import User

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'R.login_page'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')


