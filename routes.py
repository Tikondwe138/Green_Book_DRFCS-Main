import os
import ast
import folium
import json
from reportlab.pdfgen import canvas
from flask import send_file, Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_from_directory
from flask_login import login_user, logout_user, current_user, login_required
from datetime import datetime
from io import BytesIO
from models import db, AidRequest, Users, Beneficiary, Admin, Fund, Disaster, GisMap, Reports, ChatLog, VerificationLog
from flask_bcrypt import Bcrypt
from reportlab.lib.pagesizes import letter
from geopy.distance import geodesic
from forms import AddGISMapForm
from socketio_instance import socketio
from reportlab.lib import colors

routes = Blueprint('routes', __name__)

# Initialize Flask-Bcrypt
bcrypt = Bcrypt()

# Lazy import db to avoid circular import
def get_db():
    from models import db  # Import inside the function to break the circular dependency
    return db # Home route

def is_admin():
    """Check if the current user is an admin."""
    return current_user.is_authenticated and current_user.role == "admin"

# Home route
@routes.route("/")  # Use Blueprint's route instead of app.route
@login_required
def home():
    return render_template('home.html')

# Registration route
@routes.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))
    return render_template('register.html')


# Register beneficiary route
@routes.route("/register_beneficiary", methods=['GET', 'POST'])
def register_beneficiary():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        role = 'beneficiary'
        nationalid = request.form['national_id']

        # Check if the username or email already exists
        existing_user = Users.query.filter_by(name=username).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('routes.register_beneficiary'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(name=username, email=email, password=hashed_password, role=role, phone=phone)
        db.session.add(new_user)
        db.session.commit()

        # Assign role-specific details
        if role == 'admin':
            admin = Admin(user_id=new_user.user_id, department=request.form['department'])
            db.session.add(admin)
        elif role == 'beneficiary':
            beneficiary = Beneficiary(user_id=new_user.user_id, nationalid=nationalid)
            db.session.add(beneficiary)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('routes.login'))
    return render_template('register_beneficiary.html')


# Register admin route
@routes.route("/register_admin", methods=['GET', 'POST'])
def register_admin():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        role = 'admin'  # 'admin'

        # Check if the username or email already exists
        existing_user = Users.query.filter_by(name=username).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('routes.register_admin'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(name=username, email=email, password=hashed_password, role=role, phone=phone)
        db.session.add(new_user)
        db.session.commit()

        admin = Admin(user_id=new_user.user_id, department=request.form['department'])
        db.session.add(admin)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('routes.login'))
    return render_template('register_admin.html')


# Login route
@routes.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('routes.admin_Dashboard'))
        elif current_user.role == 'beneficiary':
            return redirect(url_for('routes.beneficiary_Dashboard'))
        return redirect(url_for('routes.home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = Users.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('routes.admin_Dashboard'))
            elif user.role == 'beneficiary':
                return redirect(url_for('routes.beneficiary_Dashboard'))
            flash('Login successful!', 'success')
            return redirect(url_for('routes.beneficiary_Dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
    return render_template('login.html')


# Logout route
@routes.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.login'))


# Beneficiary dashboard
@routes.route("/beneficiary_Dashboard", methods=['GET', 'POST'])
@login_required
def beneficiary_Dashboard():
    if request.method == 'GET':
        aid_requests = AidRequest.query.all()
        return render_template('beneficiary_dash.html', aid_requests=aid_requests)

    if request.method == 'POST':
        reason = request.form['reason']
        amount = request.form['amount']

        existing_beneficiary = Beneficiary.query.filter_by(user_id=current_user.user_id).first()
        beneficiary_id = existing_beneficiary.beneficiary_id

        new_aid_request = AidRequest(beneficiary_id=beneficiary_id, description=reason, amount=amount)

        db.session.add(new_aid_request)
        db.session.commit()
        flash('Aid request submitted successfully!', 'success')
        return redirect(url_for('routes.beneficiary_Dashboard'))
    return render_template('beneficiary_dash.html')


# Verify beneficiary route
@routes.route("/verify_beneficiary/<int:beneficiary_id>", methods=['POST'])
@login_required
def verify_beneficiary(beneficiary_id):
    beneficiary = Beneficiary.query.get(beneficiary_id)
    if not beneficiary:
        flash("Beneficiary not found!", "danger")
        return redirect(url_for('routes.beneficiary_Dashboard'))

    # Simulate verification score calculation (Replace with actual verification API)
    verification_score = random.randint(50, 100)
    verification_status = "Verified" if verification_score >= 70 else "Not Verified"
    beneficiary.verified = (verification_status == "Verified")
    beneficiary.verification_date = datetime.utcnow()

    # Save verification log
    verification_log = VerificationLog(
        beneficiary_id=beneficiary_id,
        status=verification_status,
        score=verification_score
    )
    db.session.add(verification_log)
    db.session.commit()

    flash(f"Verification Status: {verification_status} (Score: {verification_score})", "success")
    return redirect(url_for('routes.view_beneficiaries'))


# Admin dashboard route
@routes.route("/admin_Dashboard", methods=['GET', 'POST'])
@login_required
def admin_Dashboard():
    if request.method == 'GET':

        funds = Fund.query.all()  # Renamed from `fund`
        aid_requests = AidRequest.query.all()


        fund_data = [{"donor_name": fund.donor_name, "amount": fund.amount} for fund in funds]

        return render_template('admin_dashboard.html',
                               aid_requests=aid_requests,
                               funds=funds,
                               fund_data=json.dumps(fund_data))

    if request.method == 'POST':
        reason = request.form['reason']
        amount = request.form['amount']

        existing_beneficiary = Beneficiary.query.filter_by(user_id=current_user.user_id).first()
        if not existing_beneficiary:
            flash("Beneficiary not found!", "danger")
            return redirect(url_for('routes.admin_Dashboard'))

        beneficiary_id = existing_beneficiary.beneficiary_id
        new_aid_request = AidRequest(beneficiary_id=beneficiary_id, description=reason, amount=amount)

        db.session.add(new_aid_request)
        db.session.commit()
        flash('Aid request submitted successfully!', 'success')
        return redirect(url_for('routes.admin_Dashboard'))

    return render_template('admin_dashboard.html')



# Add disaster route
@routes.route("/add_disaster", methods=['GET', 'POST'])
@login_required
def add_disaster():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        location = request.form['location']
        severity = request.form['severity']
        status = request.form['status']

        new_disaster = Disaster(name=name, description=description, location=location, severity=severity,
                                date_occurred=datetime.utcnow(), status=status)
        db.session.add(new_disaster)
        db.session.commit()
        flash('Disaster added successfully!', 'success')
        return redirect(url_for('routes.view_disasters'))
    return render_template('add_disaster.html')


# View disasters route
@routes.route("/view_disasters")
@login_required
def view_disasters():
    disasters = Disaster.query.all()
    return render_template('view_disasters.html', disasters=disasters)

# View GIS Maps Route
@routes.route("/view_gis_maps")
@login_required
def view_gis_maps():
    db = get_db()  # Safe `db` access
    gis_maps = GisMap.query.all()

    folium_map = folium.Map(location=[-13.9626, 34.3015], zoom_start=12)

    for gis_map in gis_maps:
        coordinates = ast.literal_eval(gis_map.coordinates)
        folium.Marker(
            location=coordinates,
            popup=gis_map.name,
            icon=folium.Icon(color="green")
        ).add_to(folium_map)

    folium_map.save("templates/map.html")
    return render_template('view_gis_maps.html', gis_maps=gis_maps)

# Individual GIS Map View Route
@routes.route("/view_individual_map/<int:map_id>")
@login_required
def view_individual_map(map_id):
    gis_map = GisMap.query.get_or_404(map_id)
    coordinates = ast.literal_eval(gis_map.coordinates)

    if current_user.latitude is None or current_user.longitude is None:
        flash("User location not available. Please update your profile.", "warning")
        return redirect(url_for('routes.view_gis_maps'))

    user_location = [current_user.latitude, current_user.longitude]
    distance = geodesic(user_location, coordinates).kilometers

    folium_map = folium.Map(location=coordinates, zoom_start=12)
    folium.Marker(
        location=coordinates,
        popup=gis_map.name,
        icon=folium.Icon(color="blue")
    ).add_to(folium_map)

    folium_map.save("templates/map.html")
    return render_template('map.html', gis_map=gis_map, distance=distance)

# Add GIS Map Route
@routes.route("/add_gis_map", methods=['GET', 'POST'])
@login_required
def add_gis_map():
    form = AddGISMapForm()

    if request.method == "POST":
        if form.validate_on_submit():
            disaster_name = form.disaster_name.data
            coordinates = form.coordinates.data
            description = form.description.data

            try:
                coordinates_list = ast.literal_eval(coordinates)
                if not isinstance(coordinates_list, list) or len(coordinates_list) != 2:
                    flash("Invalid coordinates format. Use '[latitude, longitude]'.", "danger")
                    return redirect(url_for('routes.add_gis_map'))

                latitude, longitude = coordinates_list
                if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                    flash("Invalid latitude or longitude value.", "danger")
                    return redirect(url_for('routes.add_gis_map'))

            except Exception as e:
                flash(f"Invalid coordinates format: {str(e)}", "danger")
                return redirect(url_for('routes.add_gis_map'))

            disaster = Disaster.query.filter_by(name=disaster_name).first()
            if not disaster:
                flash(f"Disaster '{disaster_name}' not found.", "danger")
                return redirect(url_for('routes.add_gis_map'))

            gis_map = GisMap(
                disaster_id=disaster.disaster_id,
                coordinates=str(coordinates_list),
                name=disaster_name,
                description=description,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )

            try:
                db.session.add(gis_map)
                db.session.commit()
                flash("GIS Map added successfully!", "success")
                return redirect(url_for('routes.view_gis_maps'))
            except Exception as e:
                db.session.rollback()
                flash(f"Database error: {str(e)}", "danger")
                return redirect(url_for('routes.add_gis_map'))

        else:
            flash("Please correct form errors.", "danger")

    return render_template('add_gis_map.html', form=form)

# Delete GIS Map Route
@routes.route("/delete_gis_map/<int:map_id>", methods=['POST'])
@login_required
def delete_gis_map(map_id):
    gis_map = GisMap.query.get_or_404(map_id)

    if not current_user.is_admin:
        flash("You do not have permission to delete this map.", "danger")
        return redirect(url_for('routes.view_gis_maps'))

    db.session.delete(gis_map)
    db.session.commit()
    flash("GIS Map deleted successfully!", "success")
    return redirect(url_for('routes.view_gis_maps'))



# Fund Routes
@routes.route("/add_fund", methods=['GET', 'POST'])
@login_required
def add_fund():
    if request.method == 'POST':
        amount = request.form['amount']
        allocated_to = request.form['allocated_to']
        donor_name = request.form['donor_name']

        new_fund = Fund(amount=amount, allocated_to=allocated_to, donor_name=donor_name,
                        date_received=datetime.utcnow())
        db.session.add(new_fund)
        db.session.commit()
        flash('Fund added successfully!', 'success')
        return redirect(url_for('routes.view_funds'))
    return render_template('add_fund.html')

@routes.route("/view_funds")
@login_required
def view_funds():
    funds = Fund.query.all()
    return render_template('view_funds.html', funds=funds)

@routes.route("/fund_statistics")
def fund_statistics():
    data = Fund.query.all()
    amounts = [fund.amount for fund in data]
    donors = [fund.donor_name for fund in data]
    return jsonify({"amounts": amounts, "donors": donors})



@routes.route("/view_reports")
@login_required
def view_reports():
    """View reports based on user role."""
    reports = Reports.query.all()
    admin_status = is_admin()
    return render_template("view_reports.html", reports=reports, admin_status=admin_status)

# Generate Report Route
@routes.route('/generate_report', methods=['GET', 'POST'])
@login_required
def generate_report():
    if request.method == 'POST':
        name = request.form.get('name')
        disaster_id = request.form.get('disaster_id')
        report_data = request.form.get('report_data')

        if not name or not disaster_id or not report_data:
            flash("All fields are required.", "danger")
            return redirect(url_for('routes.generate_report'))

        new_report = Reports(
            disaster_id=int(disaster_id),
            user_id=current_user.user_id,
            title=f"Report by {name}",
            description=f"Disaster ID: {disaster_id}",
            content=report_data,
            generated_at=datetime.utcnow()  # Ensure generated_at is set
        )

        try:
            db.session.add(new_report)
            db.session.commit()
            flash("Report generated successfully!", "success")
            return redirect(url_for('routes.view_reports'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error generating report: {str(e)}", "danger")
            return redirect(url_for('routes.generate_report'))

    return render_template('generate_report.html')

# Generate PDF Route
# Define the path to save PDFs
PDF_FOLDER = r"C:\Users\Tiko\Desktop\green_book-main\static\reports"

# Ensure the folder exists
if not os.path.exists(PDF_FOLDER):
    os.makedirs(PDF_FOLDER)

@routes.route('/generate_pdf/<int:report_id>', methods=['POST'])
@login_required
def generate_pdf(report_id):
    report = Reports.query.get_or_404(report_id)
    file_path = os.path.join(PDF_FOLDER, f"report_{report_id}.pdf")

    c = canvas.Canvas(file_path, pagesize=letter)

    try:
        c.drawImage("static/images/reports_logo.png", 40, 720, width=100, height=60)
    except:
        pass

    c.setFont("Helvetica-Bold", 24)
    c.setFillColor(colors.darkgreen)
    c.drawString(160, 750, "Greenbook Malawi - Disaster Report")
    c.setFont("Helvetica", 14)
    c.setFillColor(colors.black)
    c.drawString(160, 730, "Disaster Response and Recovery Report")
    c.line(40, 720, 570, 720)

    y_position = 680
    line_spacing = 20

    def draw_section(title, value):
        nonlocal y_position
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.darkgreen)
        c.drawString(60, y_position, f"{title}:")
        c.setFont("Helvetica", 12)
        c.setFillColor(colors.black)
        c.drawString(180, y_position, value)
        y_position -= line_spacing

    draw_section("Report Title", report.title)
    draw_section("Description", report.description)
    draw_section("Disaster ID", str(report.disaster_id))

    # Ensure generated_at is not None
    generated_at_str = report.generated_at.strftime("%B %d, %Y %H:%M:%S") if report.generated_at else "N/A"
    draw_section("Generated at", generated_at_str)

    content_lines = report.content.replace("■", "\n").split("\n")
    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(colors.darkgreen)
    c.drawString(60, y_position, "Content:")
    y_position -= line_spacing

    c.setFont("Helvetica", 12)
    c.setFillColor(colors.black)
    for line in content_lines:
        wrapped_lines = [line[i:i + 80] for i in range(0, len(line), 80)]
        for wrapped_line in wrapped_lines:
            c.drawString(80, y_position, wrapped_line.strip())
            y_position -= 15

    footer_text = "Greenbook is committed to empowering individuals and communities in Malawi."
    c.setFont("Helvetica-Oblique", 9)
    c.setFillColor(colors.darkgray)
    y_position = 120
    for line in footer_text.split("\n"):
        c.drawString(60, y_position, line.strip())
        y_position -= 12

    c.save()

    return send_file(file_path, as_attachment=True, download_name=f"report_{report_id}.pdf", mimetype='application/pdf')

# Delete Report Route (Admins Only)
@routes.route('/delete_report/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    if not is_admin():
        flash("You do not have permission to delete this report.", "danger")
        return redirect(url_for('routes.view_reports'))

    report = Reports.query.get_or_404(report_id)

    try:
        db.session.delete(report)
        db.session.commit()
        flash("Report deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting report: {str(e)}", "danger")

    return redirect(url_for('routes.view_reports'))

# Update Report Route (Only Admins)
@routes.route('/update_report/<int:report_id>', methods=['GET', 'POST'])
@login_required
def update_report(report_id):
    if not is_admin():
        flash("You do not have permission to update this report.", "danger")
        return redirect(url_for('routes.view_reports'))

    report = Reports.query.get_or_404(report_id)

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        content = request.form.get('content')

        if not title or not description or not content:
            flash("All fields are required.", "danger")
            return redirect(url_for('routes.update_report', report_id=report_id))

        report.title = title
        report.description = description
        report.content = content

        try:
            db.session.commit()
            flash("Report updated successfully!", "success")
            return redirect(url_for('routes.view_reports'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating report: {str(e)}", "danger")

    return render_template('update_report.html', report=report)



# Chat page route
@routes.route("/chat")
@login_required
def chat():
    return render_template("chat.html")

# Real-Time Chat Event
@socketio.on('send_message')
def handle_message(data):
    sender = current_user.name
    message = data['message']
    receiver_id = data.get('receiver_id')  # Optional for group chat

    # Save message to the database
    chat_log = ChatLog(sender_id=current_user.user_id, receiver_id=receiver_id, message=message)
    db.session.add(chat_log)
    db.session.commit()

    # Emit message to the receiver if it's a direct message, otherwise broadcast
    if receiver_id:
        # Send to a specific user
        socketio.emit('receive_message', {'username': sender, 'message': message, 'timestamp': chat_log.timestamp}, room=receiver_id)
    else:
        # Broadcast to all users for group chat
        socketio.emit('receive_message', {'username': sender, 'message': message, 'timestamp': chat_log.timestamp}, broadcast=True)


@routes.route("/chat_history", methods=['GET'])
@login_required
def chat_history():
    # Fetch chat logs from the database
    chat_logs = ChatLog.query.order_by(ChatLog.timestamp.desc()).limit(50).all()
    return render_template("chat_history.html", chat_logs=chat_logs)

# Real-Time Notification for group chat or task updates
@socketio.on('new_notification')
def handle_notification(data):
    # Emit notification to all connected clients
    socketio.emit('receive_notification', data, broadcast=True)

# Real-Time Chat Event
@socketio.on('send_message')
def handle_message(data):
    sender = current_user.name
    message = data['message']
    receiver_id = data.get('receiver_id')  # Optional for group chat

    # Save message to the database
    chat_log = ChatLog(sender_id=current_user.user_id, receiver_id=receiver_id, message=message)
    db.session.add(chat_log)
    db.session.commit()

    # Emit message to the receiver if it's a direct message, otherwise broadcast
    if receiver_id:
        # Send to a specific user
        socketio.emit('receive_message', {'username': sender, 'message': message, 'timestamp': chat_log.timestamp}, room=receiver_id)
    else:
        # Broadcast to all users for group chat
        socketio.emit('receive_message', {'username': sender, 'message': message, 'timestamp': chat_log.timestamp}, broadcast=True)