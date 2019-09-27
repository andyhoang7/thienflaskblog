from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from sqlalchemy import desc
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.widgets import TextArea

from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os


#setting
app = Flask(__name__)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.init_app(app)

app.config['SECRET_KEY']= 'supersecret'

#set connection with Postgres
POSTGRES = {
       'user': "thien",
       'pw': "qwerty",
       'db': "blog",
       'host': "localhost",
       'port': 5432,
   }
if 'DATABASE_URL' in os.environ:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL'] 
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES


############define models
class Flags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class Likes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class Followings(db.Model):
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),primary_key=True)
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    posts = db.relationship("Posts", backref=db.backref('users', lazy=True))
    comments = db.relationship("Comments", backref=db.backref('users', lazy=True))
    flags = db.relationship('Flags', 
        backref=db.backref('users', lazy=True))
    likes = db.relationship('Likes', 
        backref=db.backref('users', lazy=True))
    
    haha = db.relationship("Followings", foreign_keys=[Followings.follower_id], backref=db.backref(
        'follower', lazy='joined'), lazy="dynamic")
    hihi = db.relationship("Followings", foreign_keys=[Followings.followed_id], backref=db.backref(
        'followed', lazy='joined'), lazy="dynamic")
    
    def set_pass(self, passw):
        self.password = generate_password_hash(passw)
        
    def check_pass(self, passw):
        return check_password_hash(self.password, passw)


    
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    body = db.Column(db.String, nullable=False)
    created = db.Column(db.DateTime, nullable=False)
    updated = db.Column(db.DateTime)
    author =  db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comments = db.relationship('Comments', backref=db.backref('posts'), lazy="dynamic")
    view_count = db.Column(db.Integer, default=0)
    flags = db.relationship('Flags',
        backref=db.backref('posts', lazy=True) )
    likes = db.relationship('Likes',
        backref=db.backref('posts', lazy=True) )

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String, nullable=False)
    created = db.Column(db.DateTime, nullable=False)
    updated = db.Column(db.DateTime)
    author =  db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    
    
db.create_all()

##############define forms
class Register(FlaskForm):
    username = StringField("User Name", validators=[DataRequired("Please input your username"), Length(min=3, max=20, message="username must have at least 3 char and max 20 chars")])
    email = StringField("Email Address", validators=[DataRequired("Please input your email"), Email("Please use @")])
    password = PasswordField("Password", validators=[DataRequired(), EqualTo("confirm")])
    confirm = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Register")
    
    def validate_username(self, field):
        if Users.query.filter_by(username=field.data).first():
            raise ValidationError("Your username has already been registered")
        
    def validate_email(self, field):
        if Users.query.filter_by(email=field.data).first():
            raise ValidationError("Your email has already been registered")

class NewPost(FlaskForm):
    title = StringField("Post Title", validators=[DataRequired(), Length(min=3,max=255, message="min 3, max 255")])
    body = StringField("Post Content", validators=[DataRequired(), Length(min=3,max=10000, message="min 3, max 10000")], widget=TextArea())
    submit = SubmitField("Post")
    
class NewComment(FlaskForm):
    body = StringField("Comment content", validators=[DataRequired(), Length(min=3, max=1000, message="min 3, max 1000")])
    submit = SubmitField("Comment")
    
    
################################
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

@app.route('/')
def home():
    if current_user.is_authenticated:
        template = ['home.html', 'includes/navbar.html', 'includes/pageheader.html']
        posts = Posts.query.order_by(desc(Posts.id))
        return render_template(template, posts=posts)
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['post', 'get'])
def register():
    form = Register()
    if request.method=="POST":
        if form.validate_on_submit():
            new_user = Users(username= form.username.data,
                             email = form.email.data,
                             )
            new_user.set_pass(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            for field_name, errors in form.errors.items():
                flash(errors)
            return redirect(url_for('register'))
    return render_template('register.html', form = form)

@app.route('/login', methods=['post','get'])
def login():
    form = Register()
    if request.method == 'POST':
        check = Users.query.filter_by(email=form.email.data).first()
        if check and check.check_pass(form.password.data):
            login_user(check)
            return redirect(url_for('profile'))
        else:
            flash("Incorrect email or password")
            return redirect(url_for('login'))
    return render_template('login.html')
        
@app.route('/logout')
def logout():
   logout_user()
   flash('please come Back.........', 'info')
   return redirect(url_for('login'))   

###############################

@app.route('/profile')
@login_required
def profile():
    template = ['profile.html', 'includes/navbar.html', 'includes/pageheader.html']
    return render_template(template, name = current_user.username)            

@app.route('/posts')
@login_required
def allposts():
    posts = Posts.query.order_by(desc(Posts.id)).all()
    return render_template('posts.html', posts = posts)   
                
@app.route('/profile/posts')
@login_required
def profileposts():
    posts = Posts.query.filter_by(author=current_user.id).order_by(desc(Posts.id)).all()
    return render_template('myposts.html', posts = posts)

@app.route('/profile/<id>/posts')
@login_required
def userposts(id):
    posts = Posts.query.filter_by(author=id).order_by(desc(Posts.id)).all()
    return render_template('myposts.html', posts = posts)

@app.route('/profile/posts/add', methods=['POST', 'GET'])
@login_required
def addpost():
    new_article = NewPost()
    if request.method == 'POST':        
        new_post = Posts(title=new_article.title.data, 
                         body=new_article.body.data,
                         created = datetime.now()) 
                         
        current_user.posts.append(new_post)
        db.session.add(new_post)
        db.session.commit()
        # flash ("You have created a new post")
        return redirect(url_for('allposts'))
    return render_template('newpost.html', form=new_article)

@app.route('/profile/posts/<id>')
@login_required
def singlepost(id):
    post = Posts.query.filter_by(id=id).first() 
    a = post.comments.all()
    post.view_count += 1
    like_count = Likes.query.filter_by(post_id=id).count()
    #check flag or not
    check_flag = Flags.query.filter_by(user_id=current_user.id, post_id = id).first()
    if check_flag :
        is_flag = True # show unflag but
    else:
        is_flag = False # show flag but
    
    check_like = Likes.query.filter_by(user_id=current_user.id, post_id = id).first()
    if check_like :
        is_liked = True # show unlike but
    else:
        is_liked = False # show like but
    # end check
    db.session.commit()
    return render_template('singlepost.html', post = post, comments = a, is_flag=is_flag, is_liked=is_liked, like_count=like_count, name=post.users.username)


@app.route('/profile/posts/<id>/flag', methods=['GET'])
@login_required
def flag_post(id):
    post = Posts.query.filter_by(id=id).first()
    check = Flags.query.filter_by(user_id=current_user.id, post_id=id).first()
    if not check:
        flag = Flags(user_id=current_user.id,
                    post_id=id)
        db.session.add(flag)
    else:
        db.session.delete(check)
    db.session.commit()
    return redirect(url_for('singlepost', id = id))

@app.route('/profile/posts/<id>/like', methods=['GET'])
@login_required
def like_post(id):
    post = Posts.query.filter_by(id=id).first()
    
    check = Likes.query.filter_by(user_id=current_user.id, post_id=id).first()
    if not check:
        like = Likes(user_id=current_user.id,
                    post_id=id)
        db.session.add(like)
    else:
        db.session.delete(check)
    db.session.commit()
    return redirect(url_for('singlepost', id = id))
        

@app.route('/profile/posts/<id>/edit', methods=['POST', 'GET'])
@login_required
def editpost(id):
    form = NewPost()
    post = Posts.query.filter_by(id=id, author = current_user.id).first()
    if not post:
        flash(["you are not allowed to edit this post"])
        return redirect(url_for("allposts"))
    else:
        if request.method == 'POST':
            post.title=form.title.data
            post.body=form.body.data
            post.updated = datetime.now()
            db.session.commit()
            return redirect(url_for('profileposts'))
        return render_template('editpost.html', form=form)
        



@app.route('/profile/posts/<id>/delete', methods=['POST', 'GET'])
@login_required
def deletepost(id):
    tobedeleted_post = Posts.query.filter_by(id=id, author=current_user.id).first()
    if tobedeleted_post:
        db.session.delete(tobedeleted_post)
        db.session.commit()
        return redirect(url_for('allposts'))
    else:
        flash(["You are not allowed to delete this post"])
        return redirect(url_for('allposts'))

    

@app.route('/profile/posts/<id>/comments/add', methods=['POST','GET'])
def newcomment(id):
  form = NewComment()
  if request.method == 'POST':
    if form.validate_on_submit():
      post = Posts.query.filter_by(id=id).first()
      c = Comments(body=form.body.data,
                    created = datetime.now(),
                    )
      current_user.comments.append(c) # autho
      post.comments.append(c)      # post
      db.session.add(c)
      db.session.commit()
      return redirect(url_for('singlepost', id=id))
    else:
      for field_name, errors in form.errors.items():
          flash(errors)
      return redirect((url_for('newcomment', id=id)))
  return render_template('newcomment.html', form = form)

@app.route('/profile/posts/<pid>/comments/<cid>/delete', methods=['POST', 'GET'])
@login_required
def deletecomment(pid, cid):
    tobedeleted_comment = Comments.query.filter_by(id=cid, author=current_user.id).first()
    if tobedeleted_comment:
        db.session.delete(tobedeleted_comment)
        db.session.commit()
        return redirect(url_for('singlepost', id=pid))
    else:
        flash(["You are not allowed to delete this comment"])
        return redirect(url_for('singlepost', id=pid))

@app.route('/profile/posts/<pid>/comments/<cid>/edit', methods=['POST', 'GET'])
@login_required
def editcomment(pid, cid):
    form = NewComment()
    comment = Comments.query.filter_by(id=cid, author = current_user.id).first()
    if not comment:
        flash(["you are not allowed to edit this comment"])
        return redirect(url_for('singlepost', id=pid))
    else:
        if request.method == 'POST':
            comment.body=form.body.data
            comment.updated = datetime.now()
            db.session.commit()
            return redirect(url_for('singlepost', id=pid))
        return render_template('editcomment.html', form=form)

@app.route('/top_posts')
def top_posts():
    posts = Posts.query.order_by(desc(Posts.view_count))
    return render_template('top_posts.html', posts=posts)

@app.route('/deleteuser/<id>')
def deleteuser(id):
    check = Users.query.filter_by(id=id).first()
    db.session.delete(check)
    db.session.commit()
    return "OK"
    

@app.route('/follow/<int:id>')
@login_required
def follow(id):
    check = Followings.query.filter_by(follower_id = current_user.id, followed_id = id).first()
    if check:
        flash(['hello, plz no'])
        return redirect(url_for('top_posts'))
    else:
        is_followed = Followings(follower_id = current_user.id, followed_id = id)

        db.session.add(is_followed)
        db.session.commit()
        return redirect(url_for('profile', id=id))

@app.route('/profile/following')
@login_required
def following():
    followings = Followings.query.filter_by(follower_id=current_user.id).all()
    return render_template('following.html', followings=followings)


if __name__ == "__main__":
    app.run(debug=True, port=5002)