
from datetime import datetime, timedelta, tzinfo
from functools import wraps
from flask import Flask, redirect, render_template, request, session
import hashlib
import pymongo
import pytz

from sessions import Session


app = Flask(__name__)
app.secret_key = b'app-secret-key'

client = pymongo.MongoClient('localhost', 27017)

db = client.app_database
user_collection = db['userData']

app.config['SESSION_MONGODB'] = client
app.config['SESSION_MONGODB_DB'] = 'app_database'
app.config['SESSION_TYPE'] = 'mongodb'


Session(app)

# ========================================================================
# Just to ensure a user is present in db

user_collection.update_one(
    {'username': 'Chetan'},
    {'$set': {'username': 'Chetan', 'password': hashlib.sha256(
        'Satpute'.encode('utf-8')).hexdigest()}},
    upsert=True)

# ========================================================================


# Inactivity timeout
# session expirs after 10 seconds of inactivity
INACTIVE_SESSION_TIMEOUT = 10

# Fixed timeout
# 20 seconds session expiry time
SESSION_EXPIRE_TIMEOUT = 20


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        username = session.get('username')
        last_access_time = session.get('last_access_time')
        expire_time = session.get('expire_time')

        if username is None or last_access_time is None or expire_time is None:
            session.clear()
            return render_template('landing_page.html')

        current_time = pytz.utc.localize(datetime.utcnow())
        inactive_duration = current_time - last_access_time

        if inactive_duration.total_seconds() > INACTIVE_SESSION_TIMEOUT or current_time > expire_time:
            session.clear()
            return render_template('landing_page.html')

        session['last_access_time'] = current_time

        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@login_required
def index():
    username = session.get('username')
    return render_template('app_dashboard.html', username=username)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template('login_page.html', error='Username and Password requried!')

        user_doc = user_collection.find_one({'username': username})
        if user_doc is None:
            return render_template('login_page.html', error='User does not exist!')

        # Store hashed password
        password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if password_hash != user_doc['password']:
            return render_template('login_page.html', error='Incorrect Password!')

        current_time = pytz.utc.localize(datetime.utcnow())
        expire_time = current_time + timedelta(seconds=SESSION_EXPIRE_TIMEOUT)

        session['username'] = username
        session['last_access_time'] = current_time
        session['expire_time'] = expire_time

        return redirect('/')

    # render login page for
    return render_template('login_page.html')


@app.route('/logout')
@login_required
def logout():
    # Delete session
    session.clear()

    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True, port=5001)
