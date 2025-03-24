from datetime import datetime, timezone
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from models import db, Users, Beneficiary, Admin, Fund, Disaster, GisMap, Reports, ChatLog, VerificationLog, AidRequest  # Ensure this path is correct
import os

# Initialize the Flask app
app = Flask(__name__)

# Ensure the directory for the database exists
db_directory = os.path.join(app.root_path, 'instance')
if not os.path.exists(db_directory):
    os.makedirs(db_directory)

# Correct database URI with full path to ensure it's accessible
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(db_directory, "greenbook.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with app
db.init_app(app)  # Initialize the db with the Flask app# Insert data into the database
# Insert Users
def insert_users():
    with app.app_context():
        db.create_all()
        users_data = [
            {'name': 'Chikondi Banda', 'email': 'chikondi@habitat.mw', 'password': 'P@ssword123', 'role': 'admin', 'phone': '+265991234567'},
            {'name': 'Thoko Jere', 'email': 'thoko@habitat.mw', 'password': 'Password123!', 'role': 'admin', 'phone': '+265884567890'},
            {'name': 'Grace Kachali', 'email': 'grace@habitat.mw', 'password': 'password1233', 'role': 'beneficiary', 'phone': '+265998765432'},
            {'name': 'Blessings Chirwa', 'email': 'blessings@habitat.mw', 'password': 'password123', 'role': 'beneficiary', 'phone': '+265882345678'},
            {'name': 'Alice Mvula', 'email': 'alice@habitat.mw', 'password': 'P@ssword123!', 'role': 'admin', 'phone': '+265992876543'},
            {'name': 'Tamara Phiri', 'email': 'tamara@habitat.mw', 'password': 'password123', 'role': 'beneficiary', 'phone': '+265881123456'},
            {'name': 'Davie Kumwenda', 'email': 'davie@habitat.mw', 'password': 'password123', 'role': 'beneficiary', 'phone': '+265887654321'},
            {'name': 'Loveness Ngoma', 'email': 'loveness@habitat.mw', 'password': 'Loveness@123', 'role': 'admin', 'phone': '+265993456789'},
            {'name': 'Kondwani Kalua', 'email': 'kondwani@habitat.mw', 'password': 'password123', 'role': 'beneficiary', 'phone': '+265884765432'},
            {'name': 'Patrick Gondwe', 'email': 'patrick@habitat.mw', 'password': 'P@trick123!', 'role': 'admin', 'phone': '+265996543210'}
        ]

        for user in users_data:
            new_user = Users(
                name=user['name'],
                email=user['email'],
                password=user['password'],
                role=user['role'],
                phone=user['phone'],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(new_user)
        db.session.commit()
        print("All users data inserted successfully.")

    # Insert Admins
def insert_admins():
    admins_data = [
        {'user_id': 1, 'department': 'Housing and WASH'},
        {'user_id': 2, 'department': 'Disaster Response'},
        {'user_id': 5, 'department': 'Community Engagement'},
        {'user_id': 8, 'department': 'Resource Mobilization'},
        {'user_id': 11, 'department': 'Data and Reporting'}
    ]

    for admin in admins_data:
        new_admin = Admin(
            user_id=admin['user_id'],
            department=admin['department']
        )
        db.session.add(new_admin)
    db.session.commit()
    print("All admin data inserted successfully.")

    # Insert Funds
def insert_funds():
    funds_data = [
        {'donor_name': 'USAID', 'amount': 12000, 'allocated_to': 1, 'date_received': datetime(2024, 8, 25, 10, 10, 10)},
        {'donor_name': 'DFID', 'amount': 15000, 'allocated_to': 2, 'date_received': datetime(2024, 9, 15, 9, 20, 45)},
        {'donor_name': 'African Development', 'amount': 20000, 'allocated_to': 3,
         'date_received': datetime(2024, 10, 10, 11, 30, 22)},
        {'donor_name': 'UN Habitat', 'amount': 25000, 'allocated_to': 4,
         'date_received': datetime(2024, 11, 5, 12, 45, 33)},
        {'donor_name': 'World Bank', 'amount': 30000, 'allocated_to': 5,
         'date_received': datetime(2024, 12, 20, 14, 10, 15)}
    ]

    for fund in funds_data:
        new_fund = Fund(
            donor_name=fund['donor_name'],
            amount=fund['amount'],
            allocated_to=fund['allocated_to'],
            date_received=fund['date_received'],
            last_updated=datetime.utcnow()
        )
        db.session.add(new_fund)
    db.session.commit()
    print("All funds data inserted successfully.")

    # Insert Beneficiaries
def insert_beneficiaries():
    beneficiaries_data = [
        {'user_id': 3, 'impact_score': 85, 'nationalid': '900112345678', 'address': 'Area 49, Lilongwe', 'verified': True, 'disaster_id': 2},
        {'user_id': 4, 'impact_score': 70, 'nationalid': '900187654321', 'address': 'Zomba Central, Zomba', 'verified': True, 'disaster_id': 3},
        {'user_id': 6, 'impact_score': 55, 'nationalid': '900111223344', 'address': 'Mzuzu North, Mzuzu', 'verified': False, 'disaster_id': 1},
        {'user_id': 7, 'impact_score': 60, 'nationalid': '900144332211', 'address': 'Ndirande, Blantyre', 'verified': True, 'disaster_id': 4},
        {'user_id': 9, 'impact_score': 40, 'nationalid': '900155667788', 'address': 'Chinsapo, Lilongwe', 'verified': False, 'disaster_id': 5}
    ]

    for beneficiary in beneficiaries_data:
        new_beneficiary = Beneficiary(
            user_id=beneficiary['user_id'],
            impact_score=beneficiary['impact_score'],
            nationalid=beneficiary['nationalid'],
            address=beneficiary['address'],
            verified=beneficiary['verified'],
            verification_date=datetime.utcnow() if beneficiary['verified'] else None,
            disaster_id=beneficiary['disaster_id']
        )
        db.session.add(new_beneficiary)
    db.session.commit()
    print("All beneficiary data inserted successfully.")

    # Insert Reports
def insert_reports():
    reports_data = [
        {'disaster_id': 1, 'user_id': 1, 'title': 'Flood Impact Report', 'description': 'Assessment of damages in Karonga', 'content': 'Extensive damage reported'},
        {'disaster_id': 2, 'user_id': 2, 'title': 'Drought Response', 'description': 'Community water distribution efforts', 'content': 'Collaboration with locals'},
        {'disaster_id': 3, 'user_id': 4, 'title': 'Cyclone Recovery Effort', 'description': 'Rehabilitation of damaged buildings', 'content': 'Focus on schools and homes'},
        {'disaster_id': 4, 'user_id': 5, 'title': 'Earthquake Aftermath', 'description': 'Immediate relief and support actions', 'content': 'Need for medical supplies'}
    ]

    for report in reports_data:
        report_obj = Reports(
            disaster_id=report['disaster_id'],
            user_id=report['user_id'],
            title=report['title'],
            description=report['description'],
            content=report['content'],
            generated_at=datetime.utcnow(),
            format_type='PDF'
        )
        db.session.add(report_obj)
    db.session.commit()
    print("All report data inserted successfully.")


    # Insert Aid Requests
def insert_aid_requests():
    aid_request_data = [
        {'beneficiary_id': 1, 'description': 'Food and water supply for 50 families', 'status': 'Approved', 'amount': 5000},
        {'beneficiary_id': 3, 'description': 'Shelter reconstruction', 'status': 'Pending', 'amount': 8000},
        {'beneficiary_id': 4, 'description': 'Medical supplies for injured victims', 'status': 'Resolved', 'amount': 3000},
        {'beneficiary_id': 5, 'description': 'Basic hygiene kits for families', 'status': 'Pending', 'amount': 1500},
        {'beneficiary_id': 2, 'description': 'Temporary shelter for displaced', 'status': 'Approved', 'amount': 2000}
    ]

    for request in aid_request_data:
        aid_request_obj = AidRequest(
            beneficiary_id=request['beneficiary_id'],
            description=request['description'],
            status=request['status'],
            amount=request['amount'],
            requested_at=datetime.utcnow()
        )
        db.session.add(aid_request_obj)
    db.session.commit()
    print("All aid request data inserted successfully.")


# Insert Disaster Data
def insert_disasters():
    with app.app_context():
        disaster_data = [
            {'name': 'Floods in Karonga', 'description': 'Heavy rains caused flooding and displacement', 'location': 'Karonga', 'severity': 'High', 'status': 'Active', 'date_occurred': datetime(2024, 12, 10, 8, 30, 0)},
            {'name': 'Cyclone Idai', 'description': 'Cyclone damage to houses and infrastructure', 'location': 'Phalombe', 'severity': 'High', 'status': 'Resolved', 'date_occurred': datetime(2024, 2, 18, 14, 0, 0)},
            {'name': 'Earthquake in Nsanje', 'description': 'Magnitude 5.2 earthquake damaging structures', 'location': 'Nsanje', 'severity': 'Medium', 'status': 'Active', 'date_occurred': datetime(2024, 9, 20, 9, 50, 0)},
            {'name': 'Wildfires in Mulanje', 'description': 'Forest fires affecting communities', 'location': 'Mulanje', 'severity': 'Low', 'status': 'Active', 'date_occurred': datetime(2024, 8, 22, 13, 10, 0)},
            {'name': 'Drought in Balaka', 'description': 'Severe drought affecting water supply', 'location': 'Balaka', 'severity': 'Medium', 'status': 'Active', 'date_occurred': datetime(2024, 11, 5, 11, 15, 0)},
            {'name': 'Flooding on Likoma Island', 'description': 'Flooding and landslides on Likoma Island', 'location': 'Likoma Island', 'severity': 'High', 'status': 'Active', 'date_occurred': datetime(2024, 10, 12, 12, 0, 0)},
            {'name': 'Flash Floods in Zomba', 'description': 'Flash floods in Zomba district', 'location': 'Zomba', 'severity': 'High', 'status': 'Active', 'date_occurred': datetime(2024, 10, 18, 13, 30, 0)},
            {'name': 'Flooding in Mchinji', 'description': 'Flooding caused by heavy rains in Mchinji', 'location': 'Mchinji', 'severity': 'Medium', 'status': 'Active', 'date_occurred': datetime(2024, 9, 8, 10, 0, 0)},
            {'name': 'Flooding in Chikwawa', 'description': 'Flooding and displacement in Chikwawa', 'location': 'Chikwawa', 'severity': 'High', 'status': 'Active', 'date_occurred': datetime(2024, 7, 22, 9, 0, 0)},
            {'name': 'Storm Damage in Lilongwe', 'description': 'Storm damage and flooding in Lilongwe', 'location': 'Lilongwe', 'severity': 'High', 'status': 'Active', 'date_occurred': datetime(2024, 6, 15, 14, 20, 0)},
            {'name': 'Drought in Neno', 'description': 'Drought causing agricultural losses', 'location': 'Neno', 'severity': 'Medium', 'status': 'Active', 'date_occurred': datetime(2024, 5, 10, 12, 10, 0)},
            {'name': 'Flooding in Kasungu', 'description': 'Flash floods in Kasungu district', 'location': 'Kasungu', 'severity': 'Medium', 'status': 'Active', 'date_occurred': datetime(2024, 4, 22, 10, 0, 0)},
            {'name': 'Landslides in Blantyre', 'description': 'Landslides in Blantyre due to heavy rain', 'location': 'Blantyre', 'severity': 'High', 'status': 'Active', 'date_occurred': datetime(2024, 3, 18, 15, 30, 0)}
        ]

        for disaster in disaster_data:
            disaster_obj = Disaster(
                name=disaster['name'],
                description=disaster['description'],
                location=disaster['location'],
                severity=disaster['severity'],
                status=disaster['status'],
                date_occurred=disaster['date_occurred'],
                # No need to pass created_at, it defaults to current time in the model
            )
            db.session.add(disaster_obj)

        db.session.commit()
    print("All disaster data inserted successfully.")

# Insert GIS Map Data
def insert_gis_maps():
    with app.app_context():
        gis_map_data = [
    {'disaster_id': 1, 'coordinates': '[-9.9459396, 33.895547]', 'name': 'Karonga Flood Map', 'description': 'Affected zones and water levels'},
    {'disaster_id': 2, 'coordinates': '[-15.7676762, 35.6370652]', 'name': 'Cyclone Idai Impact Map', 'description': 'Areas damaged by cyclone'},
    {'disaster_id': 3, 'coordinates': '[-16.9196344, 35.2363495]', 'name': 'Nsanje Earthquake Map', 'description': 'Epicenter and affected areas'},
    {'disaster_id': 4, 'coordinates': '[-16.028064, 35.4962551]', 'name': 'Mulanje Wildfires Map', 'description': 'Forest fires affecting communities'},
    {'disaster_id': 5, 'coordinates': '[-14.9924864, 34.9373051]', 'name': 'Balaka Drought Map', 'description': 'Drought impacts on water and food supply'},
    {'disaster_id': 6, 'coordinates': '[-12.0655201, 34.6934206]', 'name': 'Likoma Island Flood Map', 'description': 'Flooding and landslides on Likoma Island'},
    {'disaster_id': 7, 'coordinates': '[-15.3927981, 35.302397]', 'name': 'Zomba Flash Flood Map', 'description': 'Flash floods in Zomba district'},
    {'disaster_id': 8, 'coordinates': '[-13.7968641, 32.8883028]', 'name': 'Mchinji Floods Map', 'description': 'Flooding caused by heavy rains in Mchinji'},
    {'disaster_id': 9, 'coordinates': '[-11.702, 33.667]', 'name': 'Chikwawa Flood Map', 'description': 'Flooding and displacement in Chikwawa'},
    {'disaster_id': 10, 'coordinates': '[-16.0311277, 34.7770068]', 'name': 'Lilongwe Storm Map', 'description': 'Storm damage and flooding in Lilongwe'},
    {'disaster_id': 11, 'coordinates': '[-15.6909422, 34.3946636]', 'name': 'Neno Drought Map', 'description': 'Drought causing agricultural losses'},
    {'disaster_id': 12, 'coordinates': '[-13.0386709, 33.4399355]', 'name': 'Kasungu Flood Map', 'description': 'Flash floods in Kasungu district'},
    {'disaster_id': 13, 'coordinates': '[-15.7760278, 34.9483634]', 'name': 'Blantyre Landslide Map', 'description': 'Landslides in Blantyre due to heavy rain'}
        ]


with app.app_context():
    for gis_map in gis_map_data:
        gis_map_obj = GisMap(
            disaster_id=gis_map['disaster_id'],
            coordinates=gis_map['coordinates'],
            name=gis_map['name'],
            description=gis_map['description'],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        db.session.add(gis_map_obj)
    db.session.commit()
    print("All GIS map data inserted successfully.")

# Insert ChatLog data

# Insert ChatLog Data
def insert_chatlogs():
    with app.app_context():
        chatlog_data = [
            {'sender_id': 1, 'receiver_id': 2, 'message': 'Initial assessment complete. Awaiting further instructions.', 'timestamp': datetime(2024, 8, 10, 9, 0, 0)},
            {'sender_id': 2, 'receiver_id': 1, 'message': 'Preparing a report on the cyclone impact.', 'timestamp': datetime(2024, 8, 11, 10, 30, 0)},
            {'sender_id': 4, 'receiver_id': 5, 'message': 'Requesting additional supplies for affected areas.', 'timestamp': datetime(2024, 8, 12, 11, 45, 0)},
            {'sender_id': 5, 'receiver_id': 3, 'message': 'Community engagement ongoing. More volunteers needed.', 'timestamp': datetime(2024, 8, 15, 14, 0, 0)}
        ]

        for chat in chatlog_data:
            chatlog_obj = ChatLog(
                sender_id=chat['sender_id'],
                receiver_id=chat['receiver_id'],
                message=chat['message'],
                timestamp=chat['timestamp']
            )
            db.session.add(chatlog_obj)

        db.session.commit()
        print("All chat log data inserted successfully.")

# Insert VerificationLog data
def insert_data():
    verificationlog_data = [
        {'beneficiary_id': 1, 'verified_by': 1, 'status': 'Verified', 'remarks': 'ID and residency confirmed', 'verification_date': datetime(2024, 8, 20, 12, 0, 0)},
        {'beneficiary_id': 2, 'verified_by': 2, 'status': 'Pending', 'remarks': 'Additional documents required', 'verification_date': datetime(2024, 8, 22, 15, 30, 0)},
        {'beneficiary_id': 3, 'verified_by': 5, 'status': 'Verified', 'remarks': 'Community leader confirmed identity', 'verification_date': datetime(2024, 8, 25, 10, 0, 0)},
        {'beneficiary_id': 4, 'verified_by': 8, 'status': 'Rejected', 'remarks': 'Mismatched ID and residency', 'verification_date': datetime(2024, 8, 28, 14, 20, 0)},
        {'beneficiary_id': 5, 'verified_by': 11, 'status': 'Verified', 'remarks': 'All documents in order', 'verification_date': datetime(2024, 8, 30, 11, 0, 0)}
    ]

    # Loop through the data and add it to the session
    for log in verificationlog_data:
        verification_log = VerificationLog(
            beneficiary_id=log['beneficiary_id'],
            verified_by=log['verified_by'],
            status=log['status'],
            remarks=log['remarks'],
            verification_date=log['verification_date']
        )
        db.session.add(verification_log)

    # Commit all changes to the database at once
    db.session.commit()
    print("All verification data inserted successfully.")



# Function to initialize and insert data
def initialize_data():
    with app.app_context():  # Set up the application context here
        insert_data()  # Call the data insertion function

if __name__ == "__main__":
    initialize_data()  # Initialize data when the script is run
    insert_users()
    insert_gis_maps()
    insert_chatlogs()