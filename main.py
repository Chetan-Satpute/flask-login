from flask import Flask, redirect, render_template, request, session
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import pymongo

app = Flask(__name__)
app.secret_key = b'app-secret-key'

# Inactive lifetime of session
INACTIVE_SESSION_TIMEOUT = 10

client = pymongo.MongoClient('localhost', 27017)

db = client.app_database

user_collection = db.users
session_collection = db.sessions

# Should not create two session documents with same username
session_collection.create_index([('username', pymongo.ASCENDING)], unique=True)

# Delete session after INACTIVE_SESSION_TIMEOUT seconds of inactivity
session_collection.create_index([('last_accessed', pymongo.ASCENDING)],
                                name='session-timeout', expireAfterSeconds=INACTIVE_SESSION_TIMEOUT, background=True)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get('username')

        if username is None:
            return render_template('landing_page.html')

        # Do not consider session document last accessed before INACTIVE_SESSION_TIMEOUT seconds
        last_valid_session_access_time = datetime.utcnow()
        last_valid_session_access_time -= timedelta(
            seconds=INACTIVE_SESSION_TIMEOUT)

        session_doc = session_collection.find_one({
            'username': username,
            'last_accessed': {'$gte': last_valid_session_access_time}})

        if session_doc is None:
            return render_template('landing_page.html')

        # Update last accessed time in session document
        session_collection.update_one(
            {'username': username},
            {'$set': {'username': username, 'last_accessed': datetime.utcnow()}},
            upsert=True)

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

        # Create a session document
        session_collection.update_one(
            {'username': username},
            {'$set': {'username': username, 'last_accessed': datetime.utcnow()}},
            upsert=True)

        session['username'] = username

        return redirect('/')

    # render login page for
    return render_template('login_page.html')


@app.route('/logout')
@login_required
def logout():
    username = session.get('username')

    # Delete session
    session_collection.delete_one({'username': username})
    session.pop('username')

    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True, port=5001)

