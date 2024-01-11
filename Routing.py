from flask_login import login_user, login_required, logout_user, current_user
from flask import Blueprint, render_template, flash, url_for, session, abort, redirect, request,Flask,render_template_string
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import random
import string
from pip._vendor import cachecontrol
from flask_migrate import Migrate
import os
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
import urllib.parse
from urllib.parse import quote_plus
from __init__ import db   
import pathlib
import requests

app = Flask(__name__)

R = Blueprint('R', __name__)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
app.secret_key = 'tdhthtdy ttydtydty5dr'
migrate = Migrate(app, db)


client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret_736096332106-huf5s52ndbfdl784fqano40ur2p46mp6.apps.googleusercontent.com.json")


GOOGLE_CLIENT_ID = "736096332106-huf5s52ndbfdl784fqano40ur2p46mp6.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"



flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback",
)

@R.route('/', methods=['GET', 'POST'])
@login_required

def home():

  return render_template('home.html',user=current_user)
   
@R.route('/login')
def login_page():

  return render_template('login.html')


@R.route('/loginbygoogle')
def login_bygoogle():

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)



@R.route('/callback')
def callback():


    flow.fetch_token(authorization_response=request.url)


    if not session["state"] == request.args["state"]:
        abort(500)  


    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
        
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        plain_password = ''.join(random.choice(string.ascii_letters) for i in range(10))
        hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256')



        new_user = User(
            email=session["email"],
            first_name=session["name"],
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user
    login_user(user, remember=True)
    return redirect(url_for('R.home'))

@R.route('/share_on_telegram')
@login_required
def sharetotelegram():
    message = f"UserName: {current_user.first_name}\nEMAIL: {current_user.email}\n visit our Flask APP by Google auth my user id is :{current_user.id} "
    encoded_message = quote_plus(message)
    
    url_to_share = url_for('R.home', _external=True)
    
    telegram_url = f"https://t.me/share/url?url={quote_plus(url_to_share)}&text={encoded_message}"
    
    return redirect(telegram_url)


@R.route('/logout')
@login_required
def logout():
    logout_user()
   
    return redirect(url_for('R.login_page'))


