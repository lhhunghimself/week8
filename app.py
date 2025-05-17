#!/usr/bin/env python3
#make a flask hello world app
from flask import Flask, render_template, request, session, redirect, url_for, flash
import os
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from flask_dance.contrib.github import make_github_blueprint, github # GitHub blueprint
from flask_dance.consumer import oauth_authorized # Signal for successful OAuth
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage # For storing OAuth tokens (optional but good practice)
from sqlalchemy.orm.exc import NoResultFound

from api.fetch_data import fetch_tripadvisor_data
# Import the LoginForm class from forms.py
from forms import LoginForm, RegistrationForm, ProfileForm
from models import User, db, init_db

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Use the SECRET_KEY from environment variables for session security and Flask-Dance
app.secret_key = os.getenv('SECRET_KEY', 'fallback_secret_key_if_not_set') 
MAPBOX_ACCESS_TOKEN = os.getenv('MAPBOX_ACCESS_TOKEN')

# Configure SQLAlchemy for PostgreSQL
DB_USER = os.getenv('POSTGRES_USER', 'defaultuser')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'defaultpassword')
DB_HOST = os.getenv('POSTGRES_HOST', 'db') # 'db' is the service name in docker-compose
DB_NAME = os.getenv('POSTGRES_DB', 'defaultdb')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with our app
db.init_app(app)

# Configure Flask-Dance GitHub Blueprint
# Explicitly pass client_id and client_secret from environment variables
github_bp = make_github_blueprint(
    client_id=os.getenv("GITHUB_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_OAUTH_CLIENT_SECRET"),
    scope="user:email", # Request email scope for OIDC-like email fetching
    storage=SQLAlchemyStorage(User, db.session, user=current_user, user_required=False) # Optional: store token
)
app.register_blueprint(github_bp, url_prefix="/login")

# Initialize the database tables
# This replaces the @app.before_first_request which is no longer available in Flask 2.0+
with app.app_context():
    init_db()

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify which route to redirect to when login is required
login_manager.login_message = 'Please log in to access this page'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login user_loader callback
    
    This function is used by Flask-Login to load a user from the user_id stored in the session.
    It must return None if the ID is not valid or the user no longer exists.
    
    Args:
        user_id (str): The user_id from the session
        
    Returns:
        User: The User object if found, None otherwise
    """
    return User.query.get(int(user_id)) # Changed from User.get(user_id) to align with SQLAlchemy standard

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration:
    - GET: displays the registration form
    - POST: processes registration form, creates new user
    """
    # If user is already logged in, redirect to index page
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # Create registration form instance
    form = RegistrationForm()
    
    # Check if form was submitted and passes validation
    if form.validate_on_submit():
        # Create a new user with form data
        user = User(username=form.username.data, password=form.password.data, email=None) # Assuming email is optional for form reg
        
        # Add user to database
        db.session.add(user)
        db.session.commit()
        
        # Flash success message
        flash('Your account has been created! You can now log in.', 'success')
        
        # Redirect to login page
        return redirect(url_for('login'))
    
    # Render registration template with form
    return render_template('register.html', form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """
    User profile page where users can change their password
    
    The @login_required decorator ensures only logged-in users can access this route.
    """
    # Create profile form instance
    form = ProfileForm()
    
    # Check if form was submitted and passes validation
    if form.validate_on_submit():
        # Verify current password is correct
        # This will likely fail for OAuth users without a local password, which is fine.
        if current_user.password_hash and current_user.check_password(form.current_password.data):
            # Update password
            current_user.set_password(form.new_password.data)
            
            # Save changes to database
            db.session.commit()
            
            # Flash success message
            flash('Your password has been updated!', 'success')
            
            # Redirect to profile page (refresh)
            return redirect(url_for('profile'))
        else:
            # Current password is incorrect
            flash('Current password is incorrect.', 'danger')
    
    # Render profile template with form
    return render_template('profile.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles the login page:
    - GET: displays the login form
    - POST: processes form submission, authenticates user
    
    Uses Flask-Login to manage the user session after successful authentication.
    """
    # If user is already logged in, redirect to index page
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    # Create an instance of the LoginForm class
    form = LoginForm()
    
    # Check if form was submitted and passes all validation rules
    if form.validate_on_submit():
        # Authenticate the user with our User class method
        user = User.authenticate(form.username.data, form.password.data)
        
        if user:
            # User exists and password is correct
            # Log the user in with Flask-Login
            login_user(user)
            
            # Flash a success message
            flash('Login successful!', 'success')
            
            # Get the page the user was trying to access before login (if any)
            next_page = request.args.get('next')
            
            # Redirect to the next page or index
            return redirect(next_page or url_for('index'))
        else:
            # Authentication failed
            flash('Invalid username or password. Try logging in with GitHub.', 'danger')
    
    # Render the login template with the form
    return render_template('login.html', form=form, github_login_url=url_for("github.login"))

# OAuth authorized callback
@oauth_authorized.connect_via(github_bp)
def github_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with GitHub.", "error")
        return redirect(url_for("login"))

    resp = blueprint.session.get("/user")
    if not resp.ok:
        flash("Failed to fetch user info from GitHub.", "error")
        return redirect(url_for("login"))
    
    github_user_data = resp.json()
    github_user_id = str(github_user_data["id"])
    github_username = github_user_data["login"]
    
    # Fetch email - GitHub's OIDC-like way
    email_resp = blueprint.session.get("/user/emails")
    primary_email = None
    if email_resp.ok:
        emails = email_resp.json()
        for email_info in emails:
            if email_info["primary"] and email_info["verified"]:
                primary_email = email_info["email"]
                break
        if not primary_email and emails: # Fallback to first verified email if no primary
             for email_info in emails:
                if email_info["verified"]:
                    primary_email = email_info["email"]
                    break

    # Find or create user
    user = User.query.filter_by(github_id=github_user_id).first()
    if not user and primary_email:
        user = User.query.filter_by(email=primary_email).first()
        if user: # User exists with this email, link GitHub ID
            user.github_id = github_user_id

    if not user: # Still no user, create a new one
        # Ensure username is unique if using github_username directly
        existing_user_with_gh_username = User.query.filter_by(username=github_username).first()
        final_username = github_username
        if existing_user_with_gh_username:
            # If username exists, append part of github_id to make it unique
            final_username = f"{github_username}_{github_user_id[:5]}"

        user = User(
            username=final_username, 
            email=primary_email, 
            github_id=github_user_id
            # Password is not set, so password_hash will be None
        )
    elif user and not user.email and primary_email: # User found by github_id, update email if missing
        user.email = primary_email
    
    db.session.add(user)
    db.session.commit()
    login_user(user)
    flash("Successfully logged in with GitHub!", "success")
    return redirect(url_for("index"))

@app.route('/logout')
@login_required
def logout():
    """
    Handles user logout
    
    The @login_required decorator ensures only logged-in users can access this route.
    """
    # Log the user out with Flask-Login
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required  # Protect this route - only logged-in users can access it
def index():
    """
    Main page that displays TripAdvisor data
    
    The @login_required decorator ensures only logged-in users can access this route.
    """
    session['city'] = 'Tacoma'
    session['state'] = 'WA'
    session['category'] = 'restaurants'
    
    if request.method == 'GET':
        if request.args.get('city'):
            session['city'] = request.args.get('city')
        if request.args.get('state'):
            session['state'] = request.args.get('state')
        if request.args.get('category'):
            session['category'] = request.args.get('category')
        
    # Create a data object with business information
    location_data = fetch_tripadvisor_data(session['city'], session['state'], session['category'])
    return render_template('index.html', 
                          city=session['city'], 
                          state=session['state'], 
                          category=session['category'], 
                          location_data=location_data,
                          mapbox_access_token=MAPBOX_ACCESS_TOKEN)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
