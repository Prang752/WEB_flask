from flask import Flask
from flask import render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bootstrap import Bootstrap

from werkzeug.security import generate_password_hash, check_password_hash
import os

from datetime import datetime
import pytz

from flask_login import current_user
from flask_migrate import Migrate
from flask.cli import AppGroup


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db) 

login_manager = LoginManager()
login_manager.init_app(app)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    body = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(pytz.timezone('Asia/Bangkok')))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy=True)) 

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) or None

@app.route('/', methods=['GET'])
@login_required
def index():
    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', posts=posts)




@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Error: Username already exists!", 400 

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        user = User(username=username, password=hashed_password)


        db.session.add(user)
        db.session.commit()
        return redirect('/login')

    else:
        return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user is None or not check_password_hash(user.password, password):
            return "Invalid username or password!", 400 

        # if check_password_hash(user.password, password):
        login_user(user)
        return redirect('/')
    else:
        return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        body = request.form.get('body')

        post = Post(title=title, body=body, user_id=current_user.id)  # 🔥 ใช้ current_user.id
        db.session.add(post)
        db.session.commit()
        return redirect('/')
    return render_template('create.html')




@app.route('/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update(id):
    post = Post.query.get(id)

    if post.user_id != current_user.id:  
        return "Unauthorized", 403

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.body = request.form.get('body')
        db.session.commit()
        return redirect('/')
    return render_template('update.html', post=post)

@app.route('/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete(id):
    post = Post.query.get_or_404(id)

    if post.user_id != current_user.id:  
        return "Unauthorized", 403

    db.session.delete(post)
    db.session.commit()
    return redirect('/')

