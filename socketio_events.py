import logging
from flask_socketio import emit
from models import db, ChatLog  # Import db and ChatLog model
from socketio_instance import socketio  # Import socketio instance
# Logging Configuration
logging.basicConfig(filename='app.log', level=logging.INFO)

# Handle 'send_message' event
@socketio.on('send_message')
def handle_send_message(data):
    try:
        # Create a new ChatLog entry
        chat_message = ChatLog(sender_id=data['sender_id'], message=data['message'])
        db.session.add(chat_message)
        db.session.commit()

        # Emit the message to all connected clients
        emit('receive_message', data, broadcast=True)
        logging.info(f"Message sent by {data['sender_id']}: {data['message']}")
    except Exception as e:
        logging.error(f"Error in handle_send_message: {e}")

# Handle 'connect' event
@socketio.on('connect')
def handle_connect():
    print('Client connected')

# Handle 'disconnect' event
@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
