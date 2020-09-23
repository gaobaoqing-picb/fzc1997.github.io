#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os.path
import glob
import shutil
import datetime
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired
from sqlalchemy import desc
from flask import Flask, redirect, url_for, render_template, request, flash

#####  mac 
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user
from flask_wtf import Form
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib.fileadmin import FileAdmin
from flaskext.markdown import Markdown
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

#####  pre version
# from flask.ext.sqlalchemy import SQLAlchemy
# from flask.ext.bcrypt import Bcrypt
# from flask.ext.login import LoginManager, login_user, current_user
# from flask.ext.wtf import Form
# from flask.ext.admin import Admin, AdminIndexView, expose
# from flask.ext.admin.contrib.sqla import ModelView
# from flask.ext.admin.contrib.fileadmin import FileAdmin
# from flask.ext.markdown import Markdown
# from flask.ext.script import Manager
# from flask.ext.migrate import Migrate, MigrateCommand




###############
# Config
###############

project_path = os.path.dirname(os.path.abspath(__file__))


class Config(object):
    DEBUG = True
    SECRET_KEY = 'ejFH328^3Ds2^&2dew'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///%s/yanglab.db' % project_path


###############
# Initiation
###############

yanglab = Flask(__name__)
yanglab.config.from_object(Config)
bcrypt = Bcrypt(yanglab)
db = SQLAlchemy(yanglab)
Markdown(yanglab)
migrate = Migrate(yanglab, db)
manager = Manager(yanglab)


###############
# helper
###############

# form
class LoginForm(Form):
    username = TextField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


# jinja filters

@yanglab.template_filter('strong')
def strong(s):
    return s.replace('{{', '<strong>').replace('}}', '</strong>')


@yanglab.template_filter('split')
def split_point(s):
    return s.split('|')


###############
# Models
###############

# model for contact
class Contact(db.Model):
    __tablename__ = 'contact'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100))
    telephone = db.Column(db.String(20))
    email = db.Column(db.String(50))


# model for collaborator
class Collaborator(db.Model):
    __tablename__ = 'collaborator'
    id = db.Column(db.Integer, primary_key=True)
    info = db.Column(db.String(100))
    link = db.Column(db.String(100))


# model for support
class Support(db.Model):
    __tablename__ = 'support'
    id = db.Column(db.Integer, primary_key=True)
    info = db.Column(db.String(100))
    link = db.Column(db.String(100))


# model for link
class Link(db.Model):
    __tablename__ = 'link'
    id = db.Column(db.Integer, primary_key=True)
    info = db.Column(db.String(100))
    link = db.Column(db.String(100))


# model for research
class Research(db.Model):
    __tablename__ = 'research'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)


# model for news
class News(db.Model):
    __tablename__ = 'news'
    id = db.Column(db.Integer, primary_key=True)
    idx = db.Column(db.Integer)
    year = db.Column(db.String(10))
    month = db.Column(db.String(10))
    content = db.Column(db.Text)
    details = db.Column(db.Text)
    link = db.Column(db.String(100))
    images = db.Column(db.Text)


# model for awards
class Awards(db.Model):
    __tablename__ = 'awards'
    id = db.Column(db.Integer, primary_key=True)
    idx = db.Column(db.Integer)
    year = db.Column(db.String(10))
    content = db.Column(db.Text)
    details = db.Column(db.Text)
    images = db.Column(db.Text)


# model for pics
class Pictures(db.Model):
    __tablename__ = 'pics'
    id = db.Column(db.Integer, primary_key=True)
    idx = db.Column(db.Integer)
    year = db.Column(db.String(10))
    month = db.Column(db.String(10))
    image = db.Column(db.String(100))


# model for team
class Team(db.Model):
    __tablename__ = 'team'
    id = db.Column(db.Integer, primary_key=True)
    idx = db.Column(db.Integer)
    name = db.Column(db.String(20))
    image = db.Column(db.String(100))
    category = db.Column(db.Integer)
    title = db.Column(db.String(100))
    email = db.Column(db.String(50))
    room = db.Column(db.String(20))
    telephone = db.Column(db.String(20))
    link = db.Column(db.String(100))
    link_tag = db.Column(db.String(20))


# model for alumni
class Alumni(db.Model):
    __tablename__ = 'alumni'
    id = db.Column(db.Integer, primary_key=True)
    info = db.Column(db.Text)
    link = db.Column(db.String(100))


# model for publication
class Publication(db.Model):
    __tablename__ = 'publication'
    id = db.Column(db.Integer, primary_key=True)
    idx = db.Column(db.Integer)
    year = db.Column(db.Integer)
    title = db.Column(db.Text)
    link = db.Column(db.String(100))
    attach = db.Column(db.String(100))
    points = db.Column(db.Text)


# model for resource
class Resource(db.Model):
    __tablename__ = 'resource'
    id = db.Column(db.Integer, primary_key=True)
    classes = db.Column(db.String(20))
    name = db.Column(db.String(20))
    content = db.Column(db.Text)
    paper_link = db.Column(db.String(100))
    link = db.Column(db.String(100))


# model for supplementary
class Supplementary(db.Model):
    __tablename__ = 'supplementary'
    id = db.Column(db.Integer, primary_key=True)
    ref = db.Column(db.Integer)
    name = db.Column(db.String(100))
    content = db.Column(db.Text)
    link = db.Column(db.String(100))


# model for user
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(50))

    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password)

    # flask-Login integration
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    # required for administrative interface
    def __unicode__(self):
        return self.username


###############
# Views
###############

# view for index
@yanglab.route('/')
@yanglab.route('/index')
def index():
    attr = {}
    attr['name'] = 'home'
    picture_folder = yanglab.static_folder + '/image/pictures'
    pictures = [os.path.basename(p) for p in glob.glob(picture_folder +
                                                       '/*.jpg')]
    attr['pictures'] = pictures
    news = News.query.order_by(desc(News.idx)).limit(3)
    attr['news'] = news
    collaborators = Collaborator.query.order_by(Collaborator.id).all()
    attr['collaborators'] = collaborators
    supports = Support.query.order_by(Support.id).all()
    attr['supports'] = supports
    links = Link.query.order_by(Link.id).all()
    attr['links'] = links
    contact = Contact.query.first()
    attr['contact'] = contact

    research = Research.query.first()
    attr['research'] = research
    return render_template('index.html', **attr)


# view for research
@yanglab.route('/research')
def research():
    attr = {}
    attr['name'] = 'research'
    research = Research.query.first()
    attr['research'] = research
    return render_template('research.html', **attr)


# view for news
@yanglab.route('/news')
def news():
    attr = {}
    attr['name'] = 'news'
    news = News.query.all()
    attr['news'] = news
    return render_template('news.html', **attr)


# view for awards
@yanglab.route('/awards')
def awards():
    attr = {}
    attr['name'] = 'awards'
    awards = Awards.query.all()
    attr['awards'] = awards 
    return render_template('awards.html', **attr)


# view for pics
@yanglab.route('/pictures')
def pictures():
    attr = {}
    attr['name'] = 'pictures'
    pictures = Pictures.query.all()
    attr['pictures'] = pictures
    return render_template('pictures.html', **attr)


# view for team
@yanglab.route('/team')
def team():
    attr = {}
    attr['name'] = 'team'
    pi = Team.query.filter_by(category=0).first()

 

    attr['pi'] = pi
    stuff = Team.query.filter_by(category=1).all()
    attr['stuff'] = stuff
    student = Team.query.filter_by(category=2).all()
    attr['student'] = student
    alumni = Alumni.query.all()
    attr['alumni'] = alumni

    # print(stuff)
    # print(stuff[0].name+'\t'+stuff[0].email+'\t'+stuff[0].title)
    # for context_table in attr:
    #     print(attr[context_table])
    #     if isinstance(attr[context_table],list):
    #         print(len(attr[context_table]))
            #print(attr[context_table][0].name+'\t'+attr[context_table][0].title)
        #else:
         #   print(attr[context_table].name+'\t'+attr[context_table].title)

    return render_template('team.html', **attr)


# view for publications
@yanglab.route('/publications')
def publications():
    attr = {}
    attr['name'] = 'publications'
    #publications = Publication.query.filter(Publication.idx != -1).all()
    publications = Publication.query.filter(Publication.idx > 0).all()
    attr['publications'] = publications
    before_md = yanglab.static_folder + '/publication_before_yanglab.md'
    publication_before_yanglab = open(before_md, 'r').read()
    attr['publication_before_yanglab'] = publication_before_yanglab
    return render_template('publications.html', **attr)


# view for resources
@yanglab.route('/resources')
def resources():
    attr = {}
    attr['name'] = 'resources'
    resources = Resource.query.order_by(Resource.id).all()
    attr['resources'] = resources
    return render_template('resources.html', **attr)


# view for Supplementary
@yanglab.route('/SM')
def supplementary():
    attr = {}
    attr['name'] = 'supplementary'
    supplementaries = Supplementary.query.order_by(Supplementary.id).all()
    refs = set([entry.ref for entry in supplementaries])
    refs = sorted(list(refs))

    spmts = []
    for i in refs:
        tmp = []
        publication = Publication.query.filter_by(idx=i).first()
        related_sups = Supplementary.query.filter_by(ref=i)
        tmp.append(publication)
        tmp.append(related_sups)

        spmts.append(tmp)

    attr['spmts'] = spmts
    return render_template('supplementary.html', **attr)


# view for login
@yanglab.route('/login', methods=['GET', 'POST'])
def login():
    attr = {}
    attr['name'] = 'login'
    form = LoginForm(request.form)
    error = None
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user is not None and bcrypt.check_password_hash(user.password,
                                                           password):
            login_user(user)
            flash('You were logged in.')
            return redirect(url_for('admin.index'))
        else:
            error = 'Invalid username or password.'
    attr['form'] = form
    attr['error'] = error
    return render_template('login.html', **attr)


###############
# Controller
###############

# setting for login

login_manager = LoginManager()
login_manager.init_app(yanglab)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == int(user_id)).first()


# setting for admin

class AuthAdminIndexView(AdminIndexView):

    @expose('/')
    def index(self):
        if not current_user.is_authenticated():
            return redirect(url_for('login'))
        return super(AuthAdminIndexView, self).index()


class AuthModelView(ModelView):

    # set authorization
    def is_accessible(self):
        return current_user.is_authenticated()


class AuthFileView(FileAdmin):
    # disable directory removing
    can_delete_dirs = False
    # disable directory creation
    can_mkdir = False

    # set authorization
    def is_accessible(self):
        return current_user.is_authenticated()


admin = Admin(yanglab, 'Yang Lab Admin',
              index_view=AuthAdminIndexView(template='admin.html'))
admin.add_view(AuthModelView(Contact, db.session))
admin.add_view(AuthModelView(Collaborator, db.session))
admin.add_view(AuthModelView(Support, db.session))
admin.add_view(AuthModelView(Link, db.session))
admin.add_view(AuthModelView(Research, db.session))
admin.add_view(AuthModelView(News, db.session))
admin.add_view(AuthModelView(Awards, db.session))
admin.add_view(AuthModelView(Pictures, db.session))
admin.add_view(AuthModelView(Team, db.session))
admin.add_view(AuthModelView(Alumni, db.session))
admin.add_view(AuthModelView(Publication, db.session))
admin.add_view(AuthModelView(Resource, db.session))
admin.add_view(AuthModelView(Supplementary, db.session))
admin.add_view(AuthFileView(yanglab.static_folder + '/image',
                            name='Image Folder'))


# setting for manager

@manager.command
def init_db():
    "Initiate database."
    db.drop_all()
    db.create_all()
    db.session.add(User("admin", "test"))
    db.session.commit()


@manager.option('-u', dest='username', default='admin', help='Username.')
@manager.option('-p', dest='password', help='Password.')
def set_password(username, password):
    "Set password."
    if not password:
        sys.exit('No password!')
    else:
        print('Username: %s\nPassword: %s' % (username, password))
        current_admin = User.query.first()
        db.session.delete(current_admin)
        db.session.commit()
        db.session.add(User(username, password))
        db.session.commit()


@manager.command
def backup_db():
    "Backup database."
    today = datetime.date.today()
    shutil.copy('./yanglab.db', './yanglab_backup_%s_%s_%s.db' % (today.year,
                                                                  today.month,
                                                                  today.day))

manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    # start manager
    manager.run()
