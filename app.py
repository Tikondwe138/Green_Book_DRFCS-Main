import os
from flask import Flask
from flask_login import LoginManager
from .models import db, Users, Beneficiary, Admin, Fund, Disaster, GisMap, Reports, ChatLog, VerificationLog, AidRequest
from .routes import routes
from flask_bcrypt import Bcrypt
from .socketio_instance import socketio
from .socketio_events import handle_send_message, handle_connect, handle_disconnect  # Correct relative import
from flask_socketio import SocketIO
from flask_mail import Mail, Message
from flask_migrate import Migrate
from .forms import AddGISMapForm

# Initialize Flask app
app = Flask(__name__)

# Ensure the 'instance' directory exists
instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
os.makedirs(instance_path, exist_ok=True)

# Construct the full path to the database file
db_path = os.path.join(instance_path, "greenbook.db")

# Create an empty file if the database doesn't exist
if not os.path.exists(db_path):
    open(db_path, 'a').close()

# Configuration
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'  # Correct path format
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME', 'your_email@gmail.com'),  # Use environment variable
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD', 'your_password')  # Use environment variable
)

# Initialize extensions
db.init_app(app)  # Initialize database with app
bcrypt = Bcrypt(app)  # Initialize bcrypt for password hashing
login_manager = LoginManager(app)  # Initialize Flask-Login
login_manager.login_view = 'routes.login'
socketio = SocketIO(app, async_mode='eventlet')  # Initialize SocketIO for real-time communication

# Initialize SocketIO
socketio.init_app(app)

# Initialize Flask-Migrate for database migrations
migrate = Migrate(app, db)

# Initialize Mail extension
mail = Mail(app)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(Users, int(user_id))
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

# Register routes blueprint
app.register_blueprint(routes)

# Import event handlers for SocketIO after initializing SocketIO
from . import socketio_events  # Correct relative import to socketio_events

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return "Page not found. Please check the URL.", 404

@app.errorhandler(500)
def internal_error(e):
    return "Internal server error. Please try again later.", 500

# Initialize the database and create all tables if not already done
# **DO NOT** use `db.create_all()` here when using Flask-Migrate, this will be handled via migration commands

# Run the application with SocketIO
if __name__ == '__main__':
    socketio.run(app, debug=True)
