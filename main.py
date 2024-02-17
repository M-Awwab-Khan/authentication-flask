from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mksjdfaueirjawekrn;akudjfsioj2394u'
app.config['UPLOAD_FOLDER'] = 'static/files'

# CONFIGURE FLASK LOGIN
login_manager = LoginManager()
login_manager.init_app(app)

# LOAD USER
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(user_id)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
 
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        password = request.form['password']
        hashed_password = generate_password_hash(password, method = 'pbkdf2:sha256', salt_length=8)
        new_user = User(    
            email = request.form['email'],
            password = hashed_password,
            name = request.form['name']
        )
        db.session.add(new_user)
        db.session.commit()
        return render_template('secrets.html', name=new_user.name)

    return render_template("register.html")


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/secrets')
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 'cheat_sheet.pdf', as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
