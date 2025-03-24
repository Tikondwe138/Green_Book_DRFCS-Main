# __init__.py
from flask import Flask
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_socketio import SocketIO
from .models import AidRequest, db, Users, Beneficiary, Admin, Fund, Disaster, GisMap, Reports, ChatLog, VerificationLog
from .socketio_events import handle_send_message, handle_connect, handle_disconnect
import os

# Initialize global variables
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
socketio = SocketIO()

def create_app():
    app = Flask(__name__)  # Initialize the app

    # Configuration for the app
    app.config['SECRET_KEY'] = 'your_secret_key_here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///greenbook.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)

    # Register Blueprints
    from routes import routes
    app.register_blueprint(routes)

    # Import the event handlers after initializing socketio
    import socketio_events

    return app
