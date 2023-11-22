import student
import sys
from flask import Flask, redirect, render_template, request, session, flash, url_for, jsonify, send_file
from bson import ObjectId
from flask_bcrypt import Bcrypt
from admin import admin_app
import pymongo
from blueprints.trainer.trainer import trainer_bp
from blueprints.student.student import student_bp
from blueprints.user.user import user_bp
from pymongo import MongoClient
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.register_blueprint(trainer_bp)
app.register_blueprint(student_bp)
app.register_blueprint(user_bp)
bcrypt = Bcrypt(app)
sys.path.append("blueprints\\student\\")


client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["AMP"]
collection = db['userData']
userDatabase = client.AMP.userData
skill_collection = db['skill']
quiz_collection = db['quiz']
app.register_blueprint(admin_app, url_prefix='/admin')

app.config['PERMANENT_SESSION_LIFETIME'] = 50


session_collection = db['sessions']
# Delete session
session_collection.create_index([('expiration', pymongo.ASCENDING)],
                                name='session-timeout', expireAfterSeconds=0, background=True)


INACTIVE_SESSION_TIMEOUT = 10


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        username = session.get('username')
        last_access_time = session.get('last_access_time')

        if username is None or last_access_time is None:
            session.clear()
            return render_template('login.html')

        current_time = datetime.utcnow()
        inactive_duration = current_time - last_access_time

        if inactive_duration.total_seconds() > INACTIVE_SESSION_TIMEOUT:
            session.clear()
            return render_template('landing_page.html')

        session['last_access_time'] = current_time

        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def home():
    return render_template("Home.html")


@app.errorhandler(404)
def pageNotFound(e):
    print(e)
    return render_template('404.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        # session.setdefault()
        email = request.form.get("username")
        role = request.form.get("role")
        password = request.form.get("password")
        user = collection.find_one({"email": email})
        if role == "None":
            role = collection.find_one(
                {"email": email}, {"_id": 0, 'role': 1})['role'][0]
        # print(role_list)

        if user and bcrypt.check_password_hash(user['password'], password) and role:
            current_time = datetime.utcnow()

            session['email'] = email
            session['role'] = role
            session['last_access_time'] = current_time

            if role == "admin":
                return redirect(url_for('admin.admin_home'))
            elif role == "student":
                return redirect(url_for('student.student'))
            elif role == "trainer":
                return redirect(url_for('trainer.trainer'))

        flash("Invalid Username or Password")

    return render_template("Login.html")

# @app.route("/logout1")
# def logout1():
#     session.pop('email', None)
#     return redirect(url_for('login'))


@app.route("/back_button_detection")
def back_button_detection():
    return render_template("back_button_detetion.html")


@app.route('/download')
def download():
    path = 'questions_template.xlsx'
    return send_file(path, as_attachment=True)


# Student routes
app.add_url_rule("/quizmaster/quizzes/<quiz_id>/q/<question_id>",
                 view_func=student.display_question, methods=["GET"])
app.add_url_rule("/quizmaster/quizzes/<quiz_id>/q/<question_id>/save-next",
                 view_func=student.save_answer_option_and_next, methods=["POST"])
app.add_url_rule("/quizmaster/quizzes/<quiz_id>/q/<question_id>/save",
                 view_func=student.save_answer_option, methods=["POST"])
app.add_url_rule("/quizmaster/quizzes/<quiz_id>/noattempt",
                 view_func=student.cannot_attempt_quiz)
app.add_url_rule("/quizmaster/quizzes/<quiz_id>/submitted",
                 view_func=student.quiz_submitted)


if __name__ == '_main_':
    app.run(debug=True, port=5001)
