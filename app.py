# app.py

# from flask import Flask, render_template, request, redirect, url_for, flash
# from flask_sqlalchemy import SQLAlchemy
# from flask_mail import Mail
# from flask_wtf import FlaskForm
# from flask_login import UserMixin
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import DataRequired, Length
# from flask_login import login_user, login_required, current_user, logout_user


# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///job_board.db'
# app.config['SECRET_KEY'] = 'your_secret_key'
# app.config['MAIL_SERVER'] = 'smtp.example.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = 'your_email@example.com'
# app.config['MAIL_PASSWORD'] = 'your_email_password'

# db = SQLAlchemy(app)
# mail = Mail(app)

# class Job(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(100), nullable=False)
#     company = db.Column(db.String(100), nullable=False)
#     location = db.Column(db.String(100))
#     description = db.Column(db.Text, nullable=False)
#     email = db.Column(db.String(100), nullable=False)
# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(50), unique=True, nullable=False)
#     password = db.Column(db.String(60), nullable=False)
# class RegistrationForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
#     password = PasswordField('Password', validators=[DataRequired()])
#     submit = SubmitField('Sign Up')

# class LoginForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired()])
#     password = PasswordField('Password', validators=[DataRequired()])
#     submit = SubmitField('Log In')

# # db.create_all()

# @app.route('/')
# def index():
#     jobs = Job.query.all()
#     return render_template('index.html', jobs=jobs)

# @app.route('/job/<int:job_id>')
# def job_detail(job_id):
#     job = Job.query.get(job_id)
#     return render_template('job_detail.html', job=job)

# @app.route('/post_job', methods=['GET', 'POST'])
# def post_job():
#     if request.method == 'POST':
#         title = request.form['title']
#         company = request.form['company']
#         location = request.form['location']
#         description = request.form['description']
#         email = request.form['email']

#         job = Job(title=title, company=company, location=location, description=description, email=email)
#         db.session.add(job)
#         db.session.commit()

#         flash('Job posted successfully', 'success')
#         return redirect(url_for('index'))

#     return render_template('post_job.html')
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegistrationForm()
#     if form.validate_on_submit():
#         hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
#         user = User(username=form.username.data, password=hashed_password)
#         db.session.add(user)
#         db.session.commit()
#         flash('Your account has been created! You can now log in.', 'success')
#         return redirect(url_for('login'))
#     return render_template('register.html', form=form)

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#         app.run(debug=True)
# app.py

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_wtf import FlaskForm
from flask_login import UserMixin
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_login import login_user, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt  # Import Bcrypt
from flask_login import LoginManager  # Import LoginManager

from wtforms import ValidationError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///job_board.db"
app.config["SECRET_KEY"] = "your_secret_key"
app.config["MAIL_SERVER"] = "smtp.example.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your_email@example.com"
app.config["MAIL_PASSWORD"] = "your_email_password"
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"  # Set the login view to your login route


class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100))
    description = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(100), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def get_id(self):
        return str(self.id)


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Log In")


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=20)]
    )
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Sign Up")

    # Custom validation to check if the email is already registered
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError(
                "Email is already in use. Please choose a different one."
            )

class EditJobForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    company = StringField("Company", validators=[DataRequired()])
    location = StringField("Location")
    description = StringField("Description", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Edit Job")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def index():
    jobs = Job.query.all()
    return render_template("index.html", jobs=jobs)


@app.route("/job/<int:job_id>")
def job_detail(job_id):
    job = Job.query.get(job_id)
    return render_template("job_detail.html", job=job)


@app.route("/post_job", methods=["GET", "POST"])
def post_job():
    if request.method == "POST":
        title = request.form["title"]
        company = request.form["company"]
        location = request.form["location"]
        description = request.form["description"]
        email = request.form["email"]

        job = Job(
            title=title,
            company=company,
            location=location,
            description=description,
            email=email,
        )
        db.session.add(job)
        db.session.commit()

        flash("Job posted successfully", "success")
        return redirect(url_for("index"))

    return render_template("post_job.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Check if the user exists and the password is correct
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash("You have been logged in successfully!", "success")
            return redirect(url_for("index"))
        else:
            flash("Login failed. Please check your credentials.", "danger")
    return render_template("login.html", title="Log In", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash the password and create a new user
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user = User(
            username=form.username.data, email=form.email.data, password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        flash(
            f"Account created for {form.username.data}! You can now log in.", "success"
        )
        return redirect(url_for("login"))
    return render_template("register.html", title="Register", form=form)

@app.route("/job_listings", methods=["GET", "POST"])
@login_required
def job_listings():
    if request.method == "POST":
        # Process any actions or filters you want to implement
        pass

    jobs = Job.query.all()
    return render_template("job_listings.html", jobs=jobs)
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
