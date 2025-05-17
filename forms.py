from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
import re
from models import User

class LoginForm(FlaskForm):
    """
    Login form using Flask-WTF
    
    This form class represents the login form and handles:
    - Field definitions (username, password)
    - Validation rules
    - Custom validation methods
    """
    
    # Username field
    # - DataRequired(): Field cannot be empty
    # - Length(): Username must be between 3-30 characters
    username = StringField('Username', 
                          validators=[
                              DataRequired(message="Username is required"),
                              Length(min=3, max=30, message="Username must be between 3 and 30 characters")
                          ])
    
    # Password field (uses PasswordField which masks input)
    # - DataRequired(): Field cannot be empty
    # - Length(): Password must be between 3-30 characters
    password = PasswordField('Password',
                            validators=[
                                DataRequired(message="Password is required"),
                                Length(min=3, max=30, message="Password must be between 3 and 30 characters")
                            ])
    
    # Submit button field
    submit = SubmitField('Login')
    
    # Custom validator function for password
    # This function checks if password contains at least one capital letter and one number
    def validate_password(self, field):
        """
        Custom validator for password field
        
        Checks if the password meets complexity requirements:
        - Contains at least one capital letter
        - Contains at least one number
        
        Args:
            field: The password field to validate
        
        Raises:
            ValidationError: If password doesn't meet complexity requirements
        """
        password = field.data
        
        # Check for at least one capital letter
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one capital letter')
        
        # Check for at least one number
        if not re.search(r'[0-9]', password):
            raise ValidationError('Password must contain at least one number')


class RegistrationForm(FlaskForm):
    """
    Registration form for new users
    
    This form includes:
    - Username field with validation
    - Password field with complexity requirements
    - Password confirmation field to ensure accurate entry
    """
    username = StringField('Username', 
                          validators=[
                              DataRequired(message="Username is required"), 
                              Length(min=3, max=30, message="Username must be between 3 and 30 characters")
                          ])
    
    password = PasswordField('Password', 
                            validators=[
                                DataRequired(message="Password is required"),
                                Length(min=3, max=30, message="Password must be between 3 and 30 characters")
                            ])
    
    confirm_password = PasswordField('Confirm Password',
                                    validators=[
                                        DataRequired(message="Please confirm your password"),
                                        EqualTo('password', message="Passwords must match")
                                    ])
    
    submit = SubmitField('Register')
    
    # Check if password meets complexity requirements
    def validate_password(self, field):
        """
        Custom validator for password complexity
        
        Same validation as in LoginForm:
        - At least one capital letter
        - At least one number
        """
        password = field.data
        
        # Check for at least one capital letter
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one capital letter')
        
        # Check for at least one number
        if not re.search(r'[0-9]', password):
            raise ValidationError('Password must contain at least one number')
    
    # Check if username is already taken
    def validate_username(self, field):
        """
        Check if the username is already taken in the database
        
        Args:
            field: The username field to validate
            
        Raises:
            ValidationError: If username already exists
        """
        user = User.query.filter_by(username=field.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')


class ProfileForm(FlaskForm):
    """
    Profile form for changing passwords
    
    This form lets users:
    - Enter their current password (for verification)
    - Enter a new password 
    - Confirm the new password
    """
    current_password = PasswordField('Current Password', 
                                    validators=[
                                        DataRequired(message="Current password is required")
                                    ])
    
    new_password = PasswordField('New Password',
                                validators=[
                                    DataRequired(message="New password is required"),
                                    Length(min=3, max=30, message="Password must be between 3 and 30 characters")
                                ])
    
    confirm_password = PasswordField('Confirm New Password',
                                    validators=[
                                        DataRequired(message="Please confirm your new password"),
                                        EqualTo('new_password', message="Passwords must match")
                                    ])
    
    submit = SubmitField('Update Password')
    
    # Validate new password complexity
    def validate_new_password(self, field):
        """
        Custom validator for new password complexity
        
        Same validation as in other forms:
        - At least one capital letter
        - At least one number
        """
        password = field.data
        
        # Check for at least one capital letter
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one capital letter')
        
        # Check for at least one number
        if not re.search(r'[0-9]', password):
            raise ValidationError('Password must contain at least one number')

# Note: This is a demonstration form only
# In a real application, you would:
# - Hash passwords before storing
# - Check credentials against a database
# - Implement CSRF protection (built into Flask-WTF)
# - Add more validation like email format checking
