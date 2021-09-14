from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


## REGISTER FORM
class RegisterForm(FlaskForm):
    email = StringField(label='Email', validators=[Email()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    name = StringField(label='Name', validators=[DataRequired()])
    submit = SubmitField(label='REGISTER')


## LOGIN FORM
class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[Email()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='LET ME IN!')


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False, unique=True)
    blog_posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")
db.create_all()


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Child Relationship
    author = relationship("User", back_populates="blog_posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Parent Relationship
    comments = relationship("Comment", back_populates="post")
db.create_all()


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")

db.create_all()


## ADMIN ONLY DECORATOR
def admin_only(function):
    def wrapper(*args, **kwargs):
        print(current_user.get_id())
        print(type(current_user.get_id()))
        if current_user.get_id() != "1" or current_user.is_anonymous:
            print("Oh No")
            abort(403)
        else:
            print("Yes")
            return function(*args, **kwargs)
    wrapper.__name__ = function.__name__
    return wrapper

@app.route('/')
@login_required
def get_all_posts():
    print('get_all_posts')
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    print('register')
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data
        password = generate_password_hash(password=register_form.password.data, method='pbkdf2:sha256', salt_length=5)
        name = register_form.name.data
        if User.query.filter_by(email=email).first():
            # Account already exists
            print('exists')
            flash('There is already an account associated with this email. Please login instead.')
            return redirect(url_for('login'))
        else:
            # No existing account
            print('does not exist')
            new_user = User(email=email, password=password, name=name)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Logged in successfully')
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    print('login')
    print(current_user.get_id())
    print(current_user.is_authenticated)
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(pwhash=user.password, password=password):
                # Password Matches
                login_user(user)
                flash('Logged in successfully')
                return redirect(url_for('get_all_posts'))
            else:
                # Account Exists, Password does NOT match
                flash('Wrong password. Please try again.')
                return redirect(url_for('login'))
        else:
            # Account does NOT exist
            flash('You do not have an account registered with that email. Please register here.')
            return redirect(url_for('register'))

    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def show_post(post_id):
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        print(comment_form.comment.data)
        new_comment = Comment(text=comment_form.comment.data,
                              author_id=current_user.get_id(),
                              post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    requested_post = BlogPost.query.get(post_id)
    comments = requested_post.comments
    print(comments)
    return render_template("post.html", post=requested_post, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    print('add_new_post')
    form = CreatePostForm()
    if form.validate_on_submit():
        print('validated')
        new_post = BlogPost(title=form.title.data,
                            subtitle=form.subtitle.data,
                            body=form.body.data,
                            img_url=form.img_url.data,
                            author_id=current_user.get_id(),
                            date=date.today().strftime("%B %d, %Y")
                            )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    print('unvalidated')
    print(form.errors)
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    print('edit_form')
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    print('delete')
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
