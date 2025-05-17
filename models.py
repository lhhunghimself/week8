from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Create a SQLAlchemy instance that we'll initialize in app.py
db = SQLAlchemy()

class User(UserMixin, db.Model):
    """
    User model class that inherits from:
    - Flask-Login's UserMixin: provides authentication methods
    - SQLAlchemy's db.Model: provides database ORM functionality
    
    This model defines the 'users' table structure and methods for authentication.
    """
    __tablename__ = 'users'
    
    # Database columns
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True) # Allow null for OAuth users
    email = db.Column(db.String(120), unique=True, nullable=True) # Add email
    github_id = db.Column(db.String(120), unique=True, nullable=True) # Add github_id
    
    def __init__(self, username, password=None, email=None, github_id=None):
        """
        Initialize a new user
        
        Args:
            username: The user's username
            password: The user's plain-text password (will be hashed). Optional.
            email: The user's email address. Optional.
            github_id: The user's GitHub ID. Optional.
        """
        self.username = username
        self.email = email
        self.github_id = github_id
        # Hash the password only if provided
        if password:
            self.set_password(password)
        else:
            self.password_hash = None # Explicitly set to None for users without a local password
    
    def set_password(self, password):
        """
        Hash and store the user's password
        
        Args:
            password: The plain text password to hash
        """
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """
        Verify if the provided password matches the stored hash
        
        Args:
            password: The plain text password to check
            
        Returns:
            bool: True if password matches, False otherwise
        """
        if self.password_hash is None: # Users authenticated via OAuth may not have a password
            return False
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        """String representation of the user (for debugging)"""
        return f'<User {self.username}>'
    
    @staticmethod
    def get(user_id):
        """
        Static method to retrieve a user by ID from the database
        
        Args:
            user_id: The unique identifier of the user to find
            
        Returns:
            User: User object if found, None otherwise
        """
        return User.query.get(int(user_id))
    
    @staticmethod
    def authenticate(username, password):
        """
        Static method to check if username/password combination is valid
        
        Args:
            username: The username to validate
            password: The password to validate
            
        Returns:
            User: User object if authenticated, None otherwise
        """
        # Find the user by username
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists and password is correct
        # Also ensure password_hash is not None, meaning they have a local password
        if user and user.password_hash and user.check_password(password):
            return user
        return None


def init_db():
    """
    Initialize the database by creating all tables
    and the admin user if it doesn't exist
    """
    # Create all tables
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Create admin user
        # Provide an email for the admin user if your logic requires it, or leave as None
        admin = User(username='admin', password='Admin123', email='admin@example.com')
        db.session.add(admin)
        db.session.commit()
        print('Admin user created')
