from flask import Flask
from flask import render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_bootstrap import Bootstrap

from werkzeug.security import generate_password_hash, check_password_hash
import os

from datetime import datetime
import pytz

from flask_login import current_user
from flask_migrate import Migrate
from flask.cli import AppGroup
from flask import flash
from flask import flash, redirect, url_for, session, flash

app = Flask(__name__)
app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db) 
app.secret_key = 'your_secret_key_here'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signup"


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

    
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('This user already exists. Please try again!', 'error')  
            return redirect('/signup') 

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        user = User(username=username, password=hashed_password)

        db.session.add(user)
        db.session.commit()
        return redirect('/login')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user is None or not check_password_hash(user.password, password):
            flash('Invalid username or password!', 'error')  
            return redirect(url_for('login'))

        login_user(user)
        return redirect('/')
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


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/edit-username')
@login_required
def edit_username():
    return render_template('edit-username.html')


@app.route('/update-username', methods=['POST'])
@login_required
def update_username():
    new_username = request.form['new_username']
    current_user.username = new_username
    db.session.commit() 
    return redirect(url_for('profile')) 


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(current_user.password, old_password):
            flash('Old password is incorrect', 'danger')
            return redirect(url_for('change-password'))

    
        if new_password != confirm_password:
            flash('New password and confirmation do not match', 'danger')
            return redirect(url_for('change-password'))

    
        current_user.password = generate_password_hash(new_password)
        db.session.commit()

        flash('Your password has been updated successfully', 'success')

        login_user(current_user)  

        return redirect(url_for('profile')) 

    return render_template('change-password.html')


@app.route('/update-password', methods=['GET', 'POST'])
@login_required
def update_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

  
        if not check_password_hash(current_user.password, old_password):
            flash("Old password is incorrect!", "error")
            return redirect(url_for('update_password'))  

        
        if new_password != confirm_password:
            flash("New passwords do not match!", "error")
            return redirect(url_for('update_password'))

       
        hashed_password = generate_password_hash(new_password)

       
        current_user.password = hashed_password
        db.session.commit()

        flash("Password updated successfully!", "success")
        return redirect(url_for('profile')) 

    return render_template('change-password.html')



def get_user_by_username(username):
    user = User.query.filter_by(username=username).first()
    return user

def check_old_password(old_password, username):
    user = get_user_by_username(username)
    if user and check_password_hash(user.password, old_password):  
        return True
    return False






@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        
        # Here you can add logic to handle the contact form submission,
        # such as sending an email or saving the message to the database.
        
        flash('Thank you for your message. We will get back to you soon!', 'success')
        return redirect(url_for('contact'))
    
    return render_template('contact.html')


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        search_query = request.form.get('search_query')
        search_results = Post.query.filter(Post.title.contains(search_query)).all()
        return render_template('search_results.html', posts=search_results, query=search_query)
    return render_template('search.html')