from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
import ast
import random
import geopandas as gpd
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import login_user, logout_user, current_user, login_required
import folium
from datetime import datetime
from .models import AidRequest, db, Users, Beneficiary, Admin, Fund, Disaster, GisMap, Reports, ChatLog, VerificationLog
from flask_bcrypt import Bcrypt
from .socketio_instance import socketio
from reportlab.pdfgen import canvas
from .forms import AddGISMapForm

routes = Blueprint('routes', __name__)
bcrypt = Bcrypt()

# ----------------------------
# Helper Functions
# ----------------------------
def validate_coordinates(coordinates):
    try:
        coord_list = ast.literal_eval(coordinates)
        if isinstance(coord_list, list) and len(coord_list) == 2:
            lat, lon = coord_list
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                return True
    except (SyntaxError, ValueError):
        pass
    return False

# ----------------------------
# Home & Authentication Routes
# ----------------------------
@routes.route("/")
@login_required
def home():
    return render_template('home.html')

@routes.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('routes.admin_dashboard'))
        elif current_user.role == 'beneficiary':
            return redirect(url_for('routes.beneficiary_dashboard'))
        return redirect(url_for('routes.home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = Users.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('routes.admin_dashboard'))
            elif user.role == 'beneficiary':
                return redirect(url_for('routes.beneficiary_dashboard'))
            flash('Login successful!', 'success')
            return redirect(url_for('routes.beneficiary_dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
    return render_template('login.html')

@routes.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.login'))



# ----------------------------
# Registration Routes
# ----------------------------
@routes.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))
    return render_template('register.html')

@routes.route("/register_beneficiary", methods=['GET', 'POST'])
def register_beneficiary():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        national_id = request.form['national_id']

        existing_user = Users.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('routes.register_beneficiary'))

            # Hash the password before saving
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            try:
                # Create the new user and commit
                new_user = Users(name=username, email=email, password=hashed_password, role='beneficiary', phone=phone)
                db.session.add(new_user)
                db.session.commit()

                # Create beneficiary entry
                beneficiary = Beneficiary(user_id=new_user.user_id, nationalid=national_id)
                db.session.add(beneficiary)
                db.session.commit()

                flash('Beneficiary account created successfully!', 'success')
                return redirect(url_for('routes.login'))
            except Exception as e:
                db.session.rollback()  # Rollback in case of any errors during the database operations
                flash(f'An error occurred while creating the beneficiary: {str(e)}', 'danger')
                return redirect(url_for('routes.register_beneficiary'))

        return render_template('register_beneficiary.html')



@routes.route("/register_admin", methods=['GET', 'POST'])
def register_admin():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))
    if request.method == 'POST':
        username = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']

        existing_user = Users.query.filter_by(name=username).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('routes.register_admin'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(name=username, email=email, password=hashed_password, role='admin', phone=phone)
        db.session.add(new_user)
        db.session.commit()

        admin = Admin(user_id=new_user.user_id, department=request.form['department'])
        db.session.add(admin)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('routes.login'))
    return render_template('register_admin.html')

# ----------------------------
# Admin Dashboard Route
# ----------------------------
@routes.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('routes.home'))

    funds = Fund.query.all()
    disasters = Disaster.query.all()
    gis_maps = GisMap.query.all()
    reports = Reports.query.all()
    aid_requests = AidRequest.query.all()



    return render_template('admin_dashboard.html', funds=funds, disasters=disasters,
                           gis_maps=gis_maps, reports=reports, aid_requests=aid_requests)

# ----------------------------
# Disaster Routes (Admin)
# ----------------------------
@routes.route("/add_disaster", methods=['GET', 'POST'])
@login_required
def add_disaster():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('routes.home'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        location = request.form['location']
        severity = request.form['severity']
        status = request.form['status']
        new_disaster = Disaster(name=name, description=description, location=location,
                                severity=severity, status=status, date_occurred=datetime.utcnow())
        db.session.add(new_disaster)
        db.session.commit()
        flash('Disaster added successfully!', 'success')
        return redirect(url_for('routes.view_disasters'))
    return render_template('add_disaster.html')

@routes.route("/view_disasters")
@login_required
def view_disasters():
    disasters = Disaster.query.all()
    return render_template('view_disasters.html', disasters=disasters)

# ----------------------------
# Chat Routes
# ----------------------------
@routes.route("/chat")
@login_required
def chat():
    return render_template("chat.html")

@routes.route("/chat_history")
@login_required
def chat_history():
    chat_logs = ChatLog.query.order_by(ChatLog.timestamp.desc()).limit(50).all()
    return render_template("chat_history.html", chat_logs=chat_logs)

@routes.route("/chat_history", methods=["GET"])
def chat_history_api():
    chat_logs = ChatLog.query.order_by(ChatLog.timestamp.desc()).limit(50).all()
    chat_data = [
        {
            "username": chat.sender.name,
            "message": chat.message,
            "timestamp": chat.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        }
        for chat in chat_logs
    ]
    return jsonify(chat_data)

@socketio.on('send_message')
def handle_message(data):
    sender = current_user.name
    message = data.get('message')
    timestamp = datetime.datetime.utcnow()

    # Save the message to the database
    chat_log = ChatLog(sender_id=current_user.user_id, message=message, timestamp=timestamp)
    db.session.add(chat_log)
    db.session.commit()

    # Emit the message to all connected clients
    emit('receive_message', {
        'username': sender,
        'message': message,
        'timestamp': timestamp.strftime("%Y-%m-%d %H:%M:%S")
    }, broadcast=True)

# ----------------------------
# Real-Time Notification Handling
# ----------------------------
@socketio.on('new_notification')
def handle_notification(data):
    emit('receive_notification', data, broadcast=True)

# ----------------------------
# Beneficiary Routes
# ----------------------------
@routes.route("/verify_beneficiary/<int:beneficiary_id>", methods=['POST'])
@login_required
def verify_beneficiary(beneficiary_id):
    beneficiary = Beneficiary.query.get_or_404(beneficiary_id)

    verification_score = random.randint(50, 100)
    verification_status = "Verified" if verification_score >= 70 else "Not Verified"
    beneficiary.verified = (verification_status == "Verified")
    beneficiary.verification_date = datetime.utcnow()

    verification_log = VerificationLog(
        beneficiary_id=beneficiary_id,
        status=verification_status,
        score=verification_score
    )
    db.session.add(verification_log)
    db.session.commit()

    flash(f"Verification completed: {verification_status} (Score: {verification_score})", "success")
    return redirect(url_for('routes.admin_dashboard'))

# ----------------------------
# Beneficiary Routes
# ----------------------------
@routes.route("/beneficiary_dashboard", methods=['GET', 'POST'])
@login_required
def beneficiary_dashboard():
    if current_user.role != 'beneficiary':
        flash("Access denied.", "danger")
        return redirect(url_for('routes.home'))

    beneficiary = Beneficiary.query.filter_by(user_id=current_user.user_id).first()
    if not beneficiary:
        flash("Beneficiary not found.", "danger")
        return redirect(url_for('routes.home'))

    if request.method == 'POST':
        reason = request.form['reason']
        amount = request.form['amount']

        new_aid_request = AidRequest(
            beneficiary_id=beneficiary.beneficiary_id,
            description=reason,
            amount=amount,
            created_at=datetime.utcnow()
        )
        db.session.add(new_aid_request)
        db.session.commit()

        socketio.emit('aid_request', {
            'request_id': new_aid_request.request_id,
            'description': reason,
            'status': 'Pending',
            'amount': amount,
            'created_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }, broadcast=True)

        flash("Aid request submitted successfully!", "success")
        return redirect(url_for('routes.beneficiary_dashboard'))

    aid_requests = AidRequest.query.filter_by(beneficiary_id=beneficiary.beneficiary_id).all()
    return render_template('beneficiary_dash.html', aid_requests=aid_requests)

@routes.route("/add_aid_request", methods=['POST'])
@login_required
def add_aid_request():
    try:
        description = request.form.get('description')
        amount = request.form.get('amount')

        if not description or not amount:
            flash('Please fill out all fields!', 'danger')
            return redirect(url_for('routes.beneficiary_dashboard'))

        try:
            amount = float(amount)
        except ValueError:
            flash('Invalid amount!', 'danger')
            return redirect(url_for('routes.beneficiary_dashboard'))

        beneficiary = Beneficiary.query.filter_by(user_id=current_user.user_id).first()
        if not beneficiary:
            flash("You are not a registered beneficiary.", "danger")
            return redirect(url_for('routes.beneficiary_dashboard'))

        new_aid_request = AidRequest(
            beneficiary_id=beneficiary.beneficiary_id,
            description=description,
            amount=amount,
            created_at=datetime.utcnow()
        )
        db.session.add(new_aid_request)
        db.session.commit()

        flash('Aid request submitted successfully!', 'success')
        return redirect(url_for('routes.beneficiary_dashboard'))

    except Exception as e:
        flash(f"Error submitting aid request: {str(e)}", "danger")
        return redirect(url_for('routes.beneficiary_dashboard'))

# ----------------------------
# Fund Routes (Both Roles)
# ----------------------------
@routes.route("/add_fund", methods=['GET', 'POST'])
@login_required
def add_fund():
    if request.method == 'POST':
        donor_name = request.form.get('donor_name')
        amount = request.form.get('amount')
        allocated_to = request.form.get('allocated_to')

        if not donor_name or not amount:
            flash('Please provide all required fields!', 'danger')
            return redirect(url_for('routes.add_fund'))

        try:
            amount = float(amount)
        except ValueError:
            flash('Invalid amount!', 'danger')
            return redirect(url_for('routes.add_fund'))

        new_fund = Fund(donor_name=donor_name, amount=amount, allocated_to=allocated_to,
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

# ----------------------------
# GIS Map Routes (Admin)
# ----------------------------
@routes.route("/add_gis_map", methods=['GET', 'POST'])
@login_required
def add_gis_map():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('routes.home'))

    form = AddGISMapForm()
    if form.validate_on_submit():
        disaster_name = form.disaster_name.data
        coordinates = form.coordinates.data
        if not validate_coordinates(coordinates):
            flash("Invalid coordinates format", "danger")
            return redirect(url_for('routes.add_gis_map'))

        gis_map = GisMap(name=disaster_name, coordinates=coordinates)
        db.session.add(gis_map)
        db.session.commit()
        flash("GIS Map added successfully!", "success")
        return redirect(url_for('routes.view_gis_maps'))

    return render_template('add_gis_map.html', form=form)

@routes.route("/view_gis_maps")
@login_required
def view_gis_maps():
    gis_maps = GisMap.query.all()
    return render_template('view_gis_maps.html', gis_maps=gis_maps)

@routes.route("/view_individual_map/<int:map_id>")
@login_required
def view_individual_map(map_id):
    gis_map = GisMap.query.get_or_404(map_id)
    try:
        coordinates_list = ast.literal_eval(gis_map.coordinates)
    except:
        flash("Invalid coordinates format.", "danger")
        return redirect(url_for('routes.view_gis_maps'))

    folium_map = folium.Map(location=coordinates_list, zoom_start=12)
    folium.Marker(location=coordinates_list, popup=f"Map: {gis_map.name}", icon=folium.Icon(color="blue")).add_to(folium_map)
    folium_map.save("templates/map.html")
    return render_template('map.html')

@routes.route("/delete_gis_map/<int:map_id>", methods=['POST'])
@login_required
def delete_gis_map(map_id):
    gis_map = GisMap.query.get_or_404(map_id)
    db.session.delete(gis_map)
    db.session.commit()
    flash("GIS Map deleted successfully!", "success")
    return redirect(url_for('routes.view_gis_maps'))


# ----------------------------
# Report Routes
# ----------------------------
@routes.route('/view_reports')
@login_required
def view_reports():
    reports = Reports.query.all()  # Fetch all reports from the database
    return render_template('view_reports.html', reports=reports)

@routes.route('/generate_report', methods=['GET', 'POST'])
@login_required
def generate_report():
    if request.method == 'POST':
        name = request.form['name']
        disaster_id = request.form['disaster_id']
        report_data = request.form['report_data']

        new_report = Reports(disaster_id=int(disaster_id), user_id=current_user.user_id,
                             title=f"Report by {name}", description=report_data, content=report_data)
        db.session.add(new_report)
        db.session.commit()
        flash("Report generated successfully!", "success")
        return redirect(url_for('routes.view_reports'))  # After generating the report, redirect to the reports view page.
    return render_template('generate_report.html')

@routes.route('/delete_report/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    report = Reports.query.get_or_404(report_id)  # If report not found, return 404 error
    db.session.delete(report)
    db.session.commit()
    flash("Report deleted successfully!", "success")
    return redirect(url_for('routes.generate_report'))  # Redirect back to the generate report page

@routes.route('/generate_pdf/<int:report_id>', methods=['POST'])
@login_required
def generate_pdf(report_id):
    report = Reports.query.get_or_404(report_id)

    # Create PDF using ReportLab
    file_path = f"static/reports/report_{report_id}.pdf"
    c = canvas.Canvas(file_path, pagesize=letter)

    # Add Logo at the top (Ensure you have a logo image: 'static/reports_logo.png')
    try:
        c.drawImage("static/images/reports_logo.png", 40, 720, width=100, height=60)
    except:
        pass  # Continue without crashing if the logo is missing

    # Header
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(colors.darkgreen)
    c.drawString(160, 750, "Greenbook Malawi")
    c.setFont("Helvetica", 12)
    c.setFillColor(colors.black)
    c.drawString(160, 730, "Disaster Response and Recovery Report")
    c.line(40, 720, 570, 720)  # Horizontal line under the header

    # Report Details with Proper Spacing and Styling
    y_position = 680
    line_spacing = 25

    def draw_section(title, value):
        nonlocal y_position
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.darkgreen)
        c.drawString(60, y_position, f"{title}:")
        c.setFont("Helvetica", 12)
        c.setFillColor(colors.black)
        c.drawString(180, y_position, value)
        y_position -= line_spacing

    # Title, Description, Disaster ID, Content, and Generated At
    draw_section("Report Title", report.title)
    draw_section("Description", report.description)
    draw_section("Disaster ID", str(report.disaster_id))
    draw_section("Generated at", str(report.generated_at))

    # Content Section with Proper Line Breaks and Styling
    content_lines = report.content.replace("■", "\n").split("\n")
    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(colors.darkgreen)
    c.drawString(60, y_position, "Content:")
    y_position -= line_spacing

    c.setFont("Helvetica", 12)
    c.setFillColor(colors.black)
    for line in content_lines:
        wrapped_lines = [line[i:i+80] for i in range(0, len(line), 80)]
        for wrapped_line in wrapped_lines:
            c.drawString(80, y_position, wrapped_line.strip())
            y_position -= 15

    # Footer - Greenbook Mission and Vision with Proper Formatting
    footer_text = (
        "Greenbook is committed to empowering individuals and communities in Malawi. "
        "Our mission is to provide access to critical information that can help mitigate "
        "disasters and create a more resilient society. We aim to foster sustainable development "
        "through education, advocacy, and support. We believe that by working together, we can "
        "build a brighter future for Malawi.\n\n"
        "Thank you for being part of this mission.\n"
        "Wishing you all the best in your endeavors and hoping that this report can contribute "
        "positively to the community's well-being."
    )

    # Footer with Proper Spacing and Styling
    c.setFont("Helvetica", 10)
    c.setFillColor(colors.darkgray)
    footer_lines = footer_text.split("\n")
    y_position = 120  # Adjust footer position
    for footer_line in footer_lines:
        wrapped_footer_lines = [footer_line[i:i+90] for i in range(0, len(footer_line), 90)]
        for wrapped_footer_line in wrapped_footer_lines:
            c.drawString(60, y_position, wrapped_footer_line.strip())
            y_position -= 15

    # Save the PDF
    c.save()

    # Return the PDF as an attachment
    return send_file(file_path, as_attachment=True, download_name=f"report_{report_id}.pdf", mimetype='application/pdf')