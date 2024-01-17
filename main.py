from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# Configure Flask-login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
 
 
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    # Passing True or False if user is authenticated.
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        result = db.session.execute(db.select(User).where(User.email == email))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        error = None
        if user:
            # User already exists
            flash("You've already signed up with this email, log in instead!")
            return redirect(url_for('login'))
        
        new_user = User(
            email = request.form["email"],
            password = generate_password_hash(request.form["password"], method="pbkdf2:sha256", salt_length=8),  # hash and salted poassword
            name = request.form["name"]
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to DB.
        login_user(new_user)
        # Can redirect and get name from teh current_user
        return redirect(url_for("secrets"))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        # Find user by email provided.
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            # Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password):
                login_user(user)
                flash("You  were successfully logged in!")
                return redirect(url_for("secrets"))
            else:
                error = "Password is incorrect, please try again."
                # return redirect(url_for("login", error=error))
        else:
            error = "That email does not exist, please try again."
            # return redirect(url_for("login", error=error))
    return render_template("login.html", error=error, logged_in=current_user.is_authenticated)        

# Only logged-in users ca access this route
@app.route('/secrets')
@login_required
def secrets():
    # Passing name from current_user
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory("static", path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
