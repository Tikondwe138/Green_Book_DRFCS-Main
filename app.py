import os
from flask import Flask
from flask_login import LoginManager
from models import db, Users, Beneficiary, Admin, Fund, Disaster, GisMap, Reports, ChatLog, VerificationLog, AidRequest
from routes import routes
from flask_bcrypt import Bcrypt
from socketio_instance import socketio
from flask_socketio import SocketIO
from flask_mail import Mail, Message
from flask_migrate import Migrate
from forms import AddGISMapForm

# Initialize Flask app
app = Flask(__name__)

# Ensure the 'instance' directory exists
instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
os.makedirs(instance_path, exist_ok=True)

# Construct the full path to the database file
db_path = os.path.join(instance_path, "greenbook.db")
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
    MAIL_USERNAME=os.getenv('MAIL_USERNAME', 'your_email@gmail.com'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD', 'your_password')
)

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'routes.login'
socketio = SocketIO(app, async_mode='eventlet')  # Initialize SocketIO for real-time communication
socketio.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, int(user_id))

# Register routes blueprint
app.register_blueprint(routes, url_prefix='/')  # Ensure the blueprint is correctly registered

# Import event handlers for SocketIO after initializing SocketIO
import socketio_events  # Absolute import

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return "Page not found. Please check the URL.", 404

@app.errorhandler(500)
def internal_error(e):
    return "Internal server error. Please try again later.", 500

# Run the application with SocketIO
if __name__ == '__main__':
    socketio.run(app, debug=True)