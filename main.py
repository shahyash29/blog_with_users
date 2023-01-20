from functools import wraps

import flask
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegistrationForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

Base = declarative_base()

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False, unique=True)
    posts = relationship('BlogPost',back_populates="author")
    comments = relationship('Comment',back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer,db.ForeignKey('user.id'))
    comment_author = relationship('User',back_populates="comments")
    post_id = db.Column(db.Integer,db.ForeignKey('blog_posts.id'))
    comment_post = relationship('BlogPost',back_populates="comments")
    text = db.Column(db.Text, nullable=False)

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer,db.ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship('Comment',back_populates='comment_post')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
db.create_all()

def admins_only(f):
    @wraps(f)
    def check_admin_details(*args, **kwargs):
        if current_user.id != 1:
            return abort(403,description="Permission not allowed")
        return f(*args, **kwargs)

    return check_admin_details


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template('index.html', all_posts=posts, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user_login_form = RegistrationForm()
    if flask.request.method == 'POST' and user_login_form.validate_on_submit():
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
        user_data = User(email=request.form['email'], password=password, name=request.form['name'])
        db.session.add(user_data)
        db.session.commit()
        login_user(user_data)
        return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))
    return render_template("register.html", form=user_login_form,current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if request.method == 'POST':
        data_of_user = User.query.filter_by(email=request.form.get('email')).first()
        if not data_of_user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(data_of_user.password, request.form.get('password')):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(data_of_user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form,current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    commentForm = CommentForm()
    if request.method == 'POST' and commentForm.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Please Log in')
            return redirect(url_for('login'))
        new_comment = Comment(
            text=commentForm.body.data,
            comment_author = current_user,
            comment_post = requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post,form=commentForm,current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html",current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html",current_user=current_user)


@app.route("/new-post",methods=['GET','POST'])
@admins_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        print('yash')
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form,current_user=current_user)


@app.route("/edit-post/<int:post_id>",methods=['GET','POST'])
@admins_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,current_user=current_user)


@app.route("/delete/<int:post_id>")
@admins_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
