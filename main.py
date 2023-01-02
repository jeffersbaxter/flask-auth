import os
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

PASSWORD_METHOD = os.environ.get('PASSWORD_METHOD')
SALT_LENGTH = int(os.environ.get('SALT_LENGTH'))

app = Flask(__name__)
login_manager = LoginManager()

app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager.init_app(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def home():
    return render_template('index.html', logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        if User.query.filter_by(email=request.form['email']).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        secure_password = generate_password_hash(
            request.form['password'],
            method=PASSWORD_METHOD,
            salt_length=SALT_LENGTH
        )

        register_user = User(
            email=request.form['email'],
            password=secure_password,
            name=request.form['name']
        )

        db.session.add(register_user)
        db.session.commit()
        login_user(register_user)
        return redirect(url_for('secrets'))
    return render_template('register.html', logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = db.session.query(User).filter_by(email=email).first()

        if not user:
            flash('That email does not exist, please try again.')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password invalid, please try again')
            return redirect(url_for('login'))
        else:
            login_user(user)

            return redirect(url_for('secrets'))

    return render_template('login.html', logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template('secrets.html', name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(
        'static/files/',
        'cheat_sheet.pdf',
        as_attachment=True
    )


if __name__ == '__main__':
    app.run(debug=True)
