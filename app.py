

from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask import request, jsonify


load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True, headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type"})
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

app.config["JWT_SECRET_KEY"] = os.getenv("jwt-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class The_User(db.Model):
    __tablename__ = "the_user"
    user_id = db.Column(db.Integer, primary_key=True)
    user_role = db.Column(db.String, nullable=False)
    givenname = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)
    middle_name = db.Column(db.String)
    phone = db.Column(db.String)
    email = db.Column(db.String, unique=True, nullable=False)
    address = db.Column(db.String)
    the_password = db.Column(db.String, nullable=False)
    username = db.Column(db.String)
    salt = db.Column(db.String)
    government_id = db.Column(db.String)

    # Relationships
    aaadmin = db.relationship('The_Admin', back_populates='user', uselist=False, cascade='all, delete-orphan')
    aamaint = db.relationship('MaintenancePerson', back_populates='user', uselist=False, cascade='all, delete-orphan')
    aadriver = db.relationship('Driver', back_populates='user', uselist=False, cascade='all, delete-orphan')
    aafueling = db.relationship('FuelingPerson', back_populates='user', uselist=False, cascade='all, delete-orphan')


class The_Admin(db.Model):
    __tablename__ = "the_admin"
    admin_id = db.Column(db.Integer, db.ForeignKey("the_user.user_id"), nullable=False, primary_key=True)
    user = db.relationship("The_User", back_populates='aaadmin', uselist=False)


class MaintenancePerson(db.Model):
    __tablename__ = "maintenance_person"
    maintenance_person_id = db.Column(
        db.Integer, db.ForeignKey("the_user.user_id"), nullable=False, primary_key=True
    )
    user = db.relationship("The_User", back_populates='aamaint', uselist=False)


class Driver(db.Model):
    __tablename__ = "driver"
    driver_id = db.Column(
        db.Integer, db.ForeignKey("the_user.user_id"), nullable=False, primary_key=True
    )
    user = db.relationship("The_User", back_populates='aadriver', uselist=False)


class FuelingPerson(db.Model):
    __tablename__ = "fueling_person"
    fueling_person_id = db.Column(
        db.Integer, db.ForeignKey("the_user.user_id"), nullable=False, primary_key=True
    )
    user = db.relationship("The_User", back_populates='aafueling', uselist=False)


class Vehicle(db.Model):
    __tablename__ = "vehicle"
    vehicle_id = db.Column(db.Integer, primary_key=True)
    driver_id = db.Column(db.Integer)
    model = db.Column(db.String)
    make = db.Column(db.String)
    theyear = db.Column(db.Integer)
    license_plate = db.Column(db.String)
    sitting_capacity = db.Column(db.Integer)
    status = db.Column(db.String)
    registered_by = db.Column(db.Integer)


class AuctionVehicle(db.Model):
    __tablename__ = "auction_vehicle"
    vehicle_id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String)
    status = db.Column(db.String)
    images = db.Column(db.String)  # Assuming a string field for simplicity, consider a more suitable data type
    added_by = db.Column(db.Integer)


class MaintenanceAssignment(db.Model):
    __tablename__ = "maintenance_assignment"
    maintenance_id = db.Column(db.Integer, primary_key=True)
    thecost = db.Column(db.Float)
    date_and_time = db.Column(db.String)
    job_description = db.Column(db.String)
    created_by = db.Column(db.Integer)
    vehicle_id = db.Column(db.Integer)


class Part(db.Model):
    __tablename__ = "part"
    part_number = db.Column(db.Integer, primary_key=True)
    condition = db.Column(db.String)
    requested_by = db.Column(db.Integer)


class Fueling(db.Model):
    __tablename__ = "fueling"
    date_and_time = db.Column(db.DateTime, primary_key=True)
    fuel_amount = db.Column(db.Float)
    thecost = db.Column(db.Float)
    proof_of_fueling = db.Column(db.String)
    updated_by = db.Column(db.Integer)
    vehicle_id = db.Column(db.Integer)


class Route(db.Model):
    __tablename__ = "route"
    route_id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.String)
    end_time = db.Column(db.String)
    start_point_lang = db.Column(db.String)
    start_point_lat = db.Column(db.String)
    end_point_lang = db.Column(db.String)
    end_point_lat = db.Column(db.String)
    status = db.Column(db.String)
    thedate = db.Column(db.String)
    registered_by = db.Column(db.Integer)


class Task(db.Model):
    __tablename__ = "task"
    task_id = db.Column(db.Integer, primary_key=True)
    created_by = db.Column(db.Integer)
    route_id = db.Column(db.Integer)
    driver_id = db.Column(db.Integer)

#registering admin row by admin
@app.route('/api/the_admin/register', methods=['POST'])
def register_admin():
    data = request.get_json()

    # Assuming 'user_id' is part of the incoming data
    user_id = data.get('user_id')

    if user_id is None:
        return jsonify({'error': 'user_id is required'}), 400

    # Hash the password (assuming you have 'the_password' in the incoming data)
    hashed_password = bcrypt.generate_password_hash(data.get('the_password')).decode('utf-8')

    # Create User record with the specified user_id
    admin_user = The_User(
        user_id=user_id,
        email=data.get('email'),
        givenname=data.get('givenname'),
        surname=data.get('surname'),
        middle_name=data.get('middle_name'),
        phone=data.get('phone'),
        address=data.get('address'),
        the_password=hashed_password,
        username=data.get('username'),
        salt=data.get('salt'),
        government_id=data.get('government_id'),
        user_role='ADMIN',
    )

    # Create Admin record and associate it with the User
    admin = The_Admin(admin_id=user_id)  # Use 'user_id' from the incoming data
    admin_user.aaadmin = admin  # Associate the admin user with the admin record

    db.session.add(admin_user)
    db.session.commit()

    return jsonify({'user_id': admin_user.user_id, 'message': 'Admin registered successfully'}), 201


#logging in by admin by passing email and password. 
#output is jwt token
@app.route("/api/login", methods=["POST"])
def login_admin():
    data = request.get_json()

    alllogin = The_User.query.filter_by(email=data.get("email")).first()

    if alllogin and bcrypt.check_password_hash(
        alllogin.the_password, data.get("the_password")
    ):
        access_token = create_access_token(
            identity={
                "user_id": alllogin.user_id,
                "user_role": alllogin.user_role,
                "email": alllogin.email,
            },
            expires_delta=timedelta(days=3),
        )
        return jsonify(access_token=access_token, userole=alllogin.user_role), 200
    else:
        return jsonify({"message": "Invalid email or password"}), 401


@app.route("/api/the_admin/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


#registering maintenance person by admin. input is jwt token generated by logging in to admin
@app.route("/api/the_admin/register_maintenance_person", methods=["POST"])
@jwt_required()
def register_maintenance_person():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    data = request.get_json()

    # Assuming 'user_id' is part of the incoming data
    user_id = data.get('user_id')

    if user_id is None:
        return jsonify({'error': 'user_id is required'}), 400

    # Hash the password (assuming you have 'the_password' in the incoming data)
    hashed_password = bcrypt.generate_password_hash(data.get('the_password')).decode('utf-8')

    # Create User record with the specified user_id
    maintenance_person_user = The_User(
        user_id=user_id,
        email=data.get('email'),
        givenname=data.get('givenname'),
        surname=data.get('surname'),
        middle_name=data.get('middle_name'),
        phone=data.get('phone'),
        address=data.get('address'),
        the_password=hashed_password,
        username=data.get('username'),
        salt=data.get('salt'),
        government_id=data.get('government_id'),
        user_role='MAINTENANCE_PERSON',
    )

    # Create MaintenancePerson record and associate it with the User
    maintenance_person = MaintenancePerson(maintenance_person_id=user_id)  # Use 'user_id' from the incoming data
    maintenance_person_user.aamaint = maintenance_person  # Associate the maintenance person user with the maintenance person record

    db.session.add(maintenance_person_user)
    db.session.commit()

    return jsonify({'user_id': maintenance_person_user.user_id, 'message': 'Maintenance Person registered successfully'}), 201


#registering fueling_person by admin. input is jwt token generated by logging in to admin
@app.route("/api/the_admin/register_fueling_person", methods=["POST"])
@jwt_required()
def register_fueling_person():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    data = request.get_json()

    # Assuming 'user_id' is part of the incoming data
    user_id = data.get('user_id')

    if user_id is None:
        return jsonify({'error': 'user_id is required'}), 400

    # Hash the password (assuming you have 'the_password' in the incoming data)
    hashed_password = bcrypt.generate_password_hash(data.get('the_password')).decode('utf-8')

    # Create User record with the specified user_id
    fueling_person_user = The_User(
        user_id=user_id,
        email=data.get('email'),
        givenname=data.get('givenname'),
        surname=data.get('surname'),
        middle_name=data.get('middle_name'),
        phone=data.get('phone'),
        address=data.get('address'),
        the_password=hashed_password,
        username=data.get('username'),
        salt=data.get('salt'),
        government_id=data.get('government_id'),
        user_role='FUELING_PERSON',
    )

    # Create FuelingPerson record and associate it with the User
    fuel_person = FuelingPerson(fueling_person_id=user_id)  # Use 'user_id' from the incoming data
    fueling_person_user.aafueling = fuel_person  # Associate the fueling person user with the fueling person record

    db.session.add(fueling_person_user)
    db.session.commit()

    return jsonify({'user_id': fueling_person_user.user_id, 'message': 'Fueling Person registered successfully'}), 201


#registering driver by admin. input is jwt token generated by logging in to admin
@app.route("/api/the_admin/register_driver", methods=["POST"])
@jwt_required()
def driver_person():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    data = request.get_json()

    # Assuming 'user_id' is part of the incoming data
    user_id = data.get('user_id')

    if user_id is None:
        return jsonify({'error': 'user_id is required'}), 400

    # Hash the password (assuming you have 'the_password' in the incoming data)
    hashed_password = bcrypt.generate_password_hash(data.get('the_password')).decode('utf-8')

    # Create User record with the specified user_id
    driver_user = The_User(
        user_id=user_id,
        email=data.get('email'),
        givenname=data.get('givenname'),
        surname=data.get('surname'),
        middle_name=data.get('middle_name'),
        phone=data.get('phone'),
        address=data.get('address'),
        the_password=hashed_password,
        username=data.get('username'),
        salt=data.get('salt'),
        government_id=data.get('government_id'),
        user_role='DRIVER',
    )

    # Create FuelingPerson record and associate it with the User
    thedriver = Driver(driver_id=user_id)  # Use 'user_id' from the incoming data
    driver_user.aadriver = thedriver  # Associate the fueling person user with the fueling person record

    db.session.add(driver_user)
    db.session.commit()

    return jsonify({'user_id': driver_user.user_id, 'message': 'Driver registered successfully'}), 201


#getting all admin data. input jwt token needed
@app.route("/api/the_admin/profile", methods=["GET"])
@jwt_required()
def get_admin_profile():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    # Retrieve user_id from JWT token
    user_id = current_user.get("user_id")

    # Query The_User table to get all columns data using user_id from the token
    user = The_User.query.filter_by(user_id=user_id).first()

    if user:
        user_data = {
            "user_id": user.user_id,
            "user_role": user.user_role,
            "givenname": user.givenname,
            "surname": user.surname,
            "middle_name": user.middle_name,
            "phone": user.phone,
            "email": user.email,
            "address": user.address,
            "the_password": user.the_password,
            "username": user.username,
            "salt": user.salt,
            "government_id": user.government_id,
        }

        return jsonify(user_data)
    else:
        return jsonify({"message": "User not found"}), 404


#updating all or ceratin admin data. input jwt token needed
@app.route("/api/the_admin/profile/update", methods=["PATCH"])
@jwt_required()
def update_admin_profile():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    # Retrieve user_id from JWT token
    a_user_id = current_user.get("user_id")

    # Get the user record from The_User table
    user = The_User.query.filter_by(user_id=a_user_id).first()

    if user:
        # Update user-specific data based on the incoming JSON data
        data = request.get_json()
        user.givenname = data.get("givenname", user.givenname)
        user.surname = data.get("surname", user.surname)
        user.middle_name = data.get("middle_name", user.middle_name)
        user.phone = data.get("phone", user.phone)
        user.address = data.get("address", user.address)
        user.username = data.get("username", user.username)
        user.salt = data.get("salt", user.salt)
        user.government_id = data.get("government_id", user.government_id)

        # Commit changes to the database
        db.session.commit()

        return jsonify({"message": f"Admin profile with ID {a_user_id} updated successfully"})
    else:
        return jsonify({"message": "Admin not found"}), 404


#deleting admin data. input jwt token needed
@app.route("/api/the_admin/delete", methods=["DELETE"])
@jwt_required()
def delete_admin():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    # Retrieve user_id from JWT token
    user_id = current_user.get("user_id")

    # Query The_User table to get the user record
    admin_user = The_User.query.filter_by(user_id=user_id).first()

    if admin_user:
        # Delete the user from the The_User table
        db.session.delete(admin_user)
        db.session.commit()

        return jsonify({"message": f"Admin with ID {user_id} deleted successfully"})
    else:
        return jsonify({"message": "Admin not found"}), 404


#getiign all the users. input jwt token needed
@app.route("/api/the_admin/users", methods=["GET"])
@jwt_required()
def get_all_users_admin():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    # Query all users from the The_User table
    all_users_data = The_User.query.all()

    if all_users_data:
        users_list = [
            {
                "user_id": user.user_id,
                "user_role": user.user_role,
                "givenname": user.givenname,
                "surname": user.surname,
                "middle_name": user.middle_name,
                "phone": user.phone,
                "email": user.email,
                "address": user.address,
                "username": user.username,
                "salt": user.salt,
                "government_id": user.government_id,
            }
            for user in all_users_data
        ]
        return jsonify(users_list)
    else:
        return jsonify({"message": "No users found"}), 404
    
    
#getting user data of fuleing, maintennace perosn and driver. input jwt token needed generated when logged in from fueling, maintennace perosn or driver
@app.route("/api/three_users/get", methods=["GET"])
@jwt_required()
def get_fueling_profile():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Retrieve user_id from JWT token
    user_id = current_user.get("user_id")

    # Query The_User table to get all columns data using user_id from the token
    user = The_User.query.filter_by(user_id=user_id).first()

    if user:
        user_data = {
            "user_id": user.user_id,
            "user_role": user.user_role,
            "givenname": user.givenname,
            "surname": user.surname,
            "middle_name": user.middle_name,
            "phone": user.phone,
            "email": user.email,
            "address": user.address,
            "the_password": user.the_password,
            "username": user.username,
            "salt": user.salt,
            "government_id": user.government_id,
        }

        return jsonify(user_data)
    else:
        return jsonify({"message": "User not found"}), 404
    
    
#updating user data of fuleing, maintennace perosn and driver. input jwt token needed generated when logged in from fueling, maintennace perosn or driver
@app.route("/api/the_admin/update_three_users", methods=["PATCH"])
@jwt_required()
def update_three_users():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    data = request.get_json()
    # Get the user record from The_User table
    user = The_User.query.filter_by(user_id=data.user_id).first()

    if user:
        # Update user-specific data based on the incoming JSON data
        user.givenname = data.get("givenname", user.givenname)
        user.surname = data.get("surname", user.surname)
        user.middle_name = data.get("middle_name", user.middle_name)
        user.phone = data.get("phone", user.phone)
        user.address = data.get("address", user.address)
        user.username = data.get("username", user.username)
        user.salt = data.get("salt", user.salt)
        user.government_id = data.get("government_id", user.government_id)

        # Commit changes to the database
        db.session.commit()

        return jsonify({"message": f"Admin profile with ID {data.user_id} updated successfully"})
    else:
        return jsonify({"message": "Admin not found"}), 404


#deleting user data of fuleing, maintennace perosn and driver. input jwt token needed generated when logged in from fueling, maintennace perosn or driver
@app.route("/api/the_admin/delete_three_users", methods=["DELETE"])
@jwt_required()
def delete_three_users():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access"}), 403

    data = request.get_json()
    # Retrieve user_id from JWT token
    # Query The_User table to get the user record
    admin_user = The_User.query.filter_by(user_id=data.user_id).first()

    if admin_user:
        # Delete the user from the The_User table
        db.session.delete(admin_user)
        db.session.commit()

        return jsonify({"message": f"Admin with ID {data.user_id} deleted successfully"})
    else:
        return jsonify({"message": "Admin not found"}), 404
    
###now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features
#now we will implement System features


# Add a new vehicle:
@app.route('/api/vehicles/add', methods=['POST'])
@jwt_required()
def add_vehicle():
    # Extract user information from JWT
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    data = request.get_json()

    new_vehicle = Vehicle(
        vehicle_id=data.get('vehicle_id'),
        driver_id=data.get('driver_id'),
        model=data.get('model'),
        make=data.get('make'),
        theyear=data.get('theyear'),
        license_plate=data.get('license_plate'),
        sitting_capacity=data.get('sitting_capacity'),
        status=data.get('status'),
        registered_by=current_user.get("user_id")
    )

    db.session.add(new_vehicle)
    db.session.commit()

    return jsonify({'message': 'Vehicle added successfully'}), 201


#Get all vehicles:
@app.route('/api/vehicles', methods=['GET'])
def get_all_vehicles():
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403
    
    vehicles = Vehicle.query.all()

    if vehicles:
        vehicle_list = [{
            'vehicle_id': vehicle.vehicle_id,
            'driver_id': vehicle.driver_id,
            'model': vehicle.model,
            'make': vehicle.make,
            'theyear': vehicle.theyear,
            'license_plate': vehicle.license_plate,
            'sitting_capacity': vehicle.sitting_capacity,
            'status': vehicle.status,
            'registered_by': vehicle.registered_by
        } for vehicle in vehicles]

        return jsonify(vehicle_list)
    else:
        return jsonify({'message': 'No vehicles found'}), 404
    
    
# Update Vehicle
@app.route('/api/vehicles/update/<int:vehicle_id>', methods=['PUT'])
@jwt_required()
def update_vehicle(vehicle_id):
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    vehicle = Vehicle.query.get(vehicle_id)

    if not vehicle:
        return jsonify({"message": "Vehicle not found"}), 404

    data = request.get_json()

    vehicle.driver_id = data.get('driver_id', vehicle.driver_id)
    vehicle.model = data.get('model', vehicle.model)
    vehicle.make = data.get('make', vehicle.make)
    vehicle.theyear = data.get('theyear', vehicle.theyear)
    vehicle.license_plate = data.get('license_plate', vehicle.license_plate)
    vehicle.sitting_capacity = data.get('sitting_capacity', vehicle.sitting_capacity)
    vehicle.status = data.get('status', vehicle.status)

    db.session.commit()

    return jsonify({'message': 'Vehicle updated successfully'}), 200


# Delete Vehicle
@app.route('/api/vehicles/delete/<int:vehicle_id>', methods=['DELETE'])
@jwt_required()
def delete_vehicle(vehicle_id):
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    vehicle = Vehicle.query.get(vehicle_id)

    if not vehicle:
        return jsonify({"message": "Vehicle not found"}), 404

    db.session.delete(vehicle)
    db.session.commit()

    return jsonify({'message': 'Vehicle deleted successfully'}), 200
    
    
#Add a new auction vehicle:
@app.route('/api/auction-vehicles/add', methods=['POST'])
@jwt_required()
def add_auction_vehicle():
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403
    
    data = request.get_json()

    new_auction_vehicle = AuctionVehicle(
        vehicle_id=data.get('vehicle_id'),
        description=data.get('description'),
        status=data.get('status'),
        images=data.get('images'),
        added_by=data.get('added_by')
    )

    db.session.add(new_auction_vehicle)
    db.session.commit()

    return jsonify({'message': 'Auction Vehicle added successfully'}), 201


# Get all auction vehicles:
@app.route('/api/auction-vehicles', methods=['GET'])
def get_all_auction_vehicles():
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403
    
    auction_vehicles = AuctionVehicle.query.all()

    if auction_vehicles:
        auction_vehicle_list = [{
            'vehicle_id': auction_vehicle.vehicle_id,
            'description': auction_vehicle.description,
            'status': auction_vehicle.status,
            'images': auction_vehicle.images,
            'added_by': auction_vehicle.added_by
        } for auction_vehicle in auction_vehicles]

        return jsonify(auction_vehicle_list)
    else:
        return jsonify({'message': 'No auction vehicles found'}), 404
    

# Update AuctionVehicle
@app.route('/api/auction-vehicles/update/<int:vehicle_id>', methods=['PUT'])
@jwt_required()
def update_auction_vehicle(vehicle_id):
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    auction_vehicle = AuctionVehicle.query.get(vehicle_id)

    if not auction_vehicle:
        return jsonify({"message": "Auction Vehicle not found"}), 404

    data = request.get_json()

    auction_vehicle.description = data.get('description', auction_vehicle.description)
    auction_vehicle.status = data.get('status', auction_vehicle.status)
    auction_vehicle.images = data.get('images', auction_vehicle.images)
    auction_vehicle.added_by = data.get('added_by', auction_vehicle.added_by)

    db.session.commit()

    return jsonify({'message': 'Auction Vehicle updated successfully'}), 200


# Delete AuctionVehicle
@app.route('/api/auction-vehicles/delete/<int:vehicle_id>', methods=['DELETE'])
@jwt_required()
def delete_auction_vehicle(vehicle_id):
    current_user = get_jwt_identity()

    # Check if the user has the admin role
    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    auction_vehicle = AuctionVehicle.query.get(vehicle_id)

    if not auction_vehicle:
        return jsonify({"message": "Auction Vehicle not found"}), 404

    db.session.delete(auction_vehicle)
    db.session.commit()

    return jsonify({'message': 'Auction Vehicle deleted successfully'}), 200


# Add MaintenanceAssignment
@app.route('/api/maintenance-assignments/add', methods=['POST'])
@jwt_required()
def add_maintenance_assignment():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" or current_user.get("user_role") != "MAINTENANCE_PERSON":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    data = request.get_json()

    new_maintenance_assignment = MaintenanceAssignment(
        maintenance_id=data.get('maintenance_id'),
        thecost=data.get('thecost'),
        date_and_time=data.get('date_and_time'),
        job_description=data.get('job_description'),
        created_by=data.get('created_by'),
        vehicle_id=data.get('vehicle_id')
    )

    db.session.add(new_maintenance_assignment)
    db.session.commit()

    return jsonify({'message': 'Maintenance Assignment added successfully'}), 201


# Get MaintenanceAssignment
@app.route('/api/maintenance-assignments', methods=['GET'])
@jwt_required()
def get_maintenance_assignments():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" or current_user.get("user_role") != "MAINTENANCE_PERSON":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    maintenance_assignments = MaintenanceAssignment.query.all()

    if maintenance_assignments:
        assignments_list = [
            {
                "maintenance_id": assignment.maintenance_id,
                "thecost": assignment.thecost,
                "date_and_time": assignment.date_and_time,
                "job_description": assignment.job_description,
                "created_by": assignment.created_by,
                "vehicle_id": assignment.vehicle_id
            }
            for assignment in maintenance_assignments
        ]
        return jsonify(assignments_list)
    else:
        return jsonify({"message": "No maintenance assignments found"}), 404
    

# Update MaintenanceAssignment
@app.route('/api/maintenance-assignments/update/<int:maintenance_id>', methods=['PUT'])
@jwt_required()
def update_maintenance_assignment(maintenance_id):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" and current_user.get("user_role") != "MAINTENANCE_PERSON":
        return jsonify({"message": "Unauthorized access. Admin or Maintenance Person role required."}), 403

    maintenance_assignment = MaintenanceAssignment.query.get(maintenance_id)

    if not maintenance_assignment:
        return jsonify({"message": "Maintenance Assignment not found"}), 404

    data = request.get_json()

    maintenance_assignment.thecost = data.get('thecost', maintenance_assignment.thecost)
    maintenance_assignment.date_and_time = data.get('date_and_time', maintenance_assignment.date_and_time)
    maintenance_assignment.job_description = data.get('job_description', maintenance_assignment.job_description)
    maintenance_assignment.created_by = data.get('created_by', maintenance_assignment.created_by)
    maintenance_assignment.vehicle_id = data.get('vehicle_id', maintenance_assignment.vehicle_id)

    db.session.commit()

    return jsonify({'message': 'Maintenance Assignment updated successfully'}), 200


# Delete MaintenanceAssignment
@app.route('/api/maintenance-assignments/delete/<int:maintenance_id>', methods=['DELETE'])
@jwt_required()
def delete_maintenance_assignment(maintenance_id):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" and current_user.get("user_role") != "MAINTENANCE_PERSON":
        return jsonify({"message": "Unauthorized access. Admin or Maintenance Person role required."}), 403

    maintenance_assignment = MaintenanceAssignment.query.get(maintenance_id)

    if not maintenance_assignment:
        return jsonify({"message": "Maintenance Assignment not found"}), 404

    db.session.delete(maintenance_assignment)
    db.session.commit()

    return jsonify({'message': 'Maintenance Assignment deleted successfully'}), 200


# Add Part
@app.route('/api/parts/add', methods=['POST'])
@jwt_required()
def add_part():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" or current_user.get("user_role") != "MAINTENANCE_PERSON":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    data = request.get_json()

    new_part = Part(
        part_number=data.get('part_number'),
        condition=data.get('condition'),
        requested_by=data.get('requested_by')
    )

    db.session.add(new_part)
    db.session.commit()

    return jsonify({'message': 'Part added successfully'}), 201


# Get Part
@app.route('/api/parts', methods=['GET'])
@jwt_required()
def get_parts():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" or current_user.get("user_role") != "MAINTENANCE_PERSON":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    parts = Part.query.all()

    if parts:
        parts_list = [
            {
                "part_number": part.part_number,
                "condition": part.condition,
                "requested_by": part.requested_by
            }
            for part in parts
        ]
        return jsonify(parts_list)
    else:
        return jsonify({"message": "No parts found"}), 404
    

# Update Part
@app.route('/api/parts/update/<int:part_number>', methods=['PUT'])
@jwt_required()
def update_part(part_number):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" and current_user.get("user_role") != "MAINTENANCE_PERSON":
        return jsonify({"message": "Unauthorized access. Admin or Maintenance Person role required."}), 403

    part = Part.query.get(part_number)

    if not part:
        return jsonify({"message": "Part not found"}), 404

    data = request.get_json()

    part.condition = data.get('condition', part.condition)
    part.requested_by = data.get('requested_by', part.requested_by)

    db.session.commit()

    return jsonify({'message': 'Part updated successfully'}), 200


# Delete Part
@app.route('/api/parts/delete/<int:part_number>', methods=['DELETE'])
@jwt_required()
def delete_part(part_number):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" and current_user.get("user_role") != "MAINTENANCE_PERSON":
        return jsonify({"message": "Unauthorized access. Admin or Maintenance Person role required."}), 403

    part = Part.query.get(part_number)

    if not part:
        return jsonify({"message": "Part not found"}), 404

    db.session.delete(part)
    db.session.commit()

    return jsonify({'message': 'Part deleted successfully'}), 200


# Add Fueling
@app.route('/api/fuelings/add', methods=['POST'])
@jwt_required()
def add_fueling():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" or current_user.get("user_role") != "FUELING_PERSON":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    data = request.get_json()

    new_fueling = Fueling(
        date_and_time=data.get('date_and_time'),
        fuel_amount=data.get('fuel_amount'),
        thecost=data.get('thecost'),
        proof_of_fueling=data.get('proof_of_fueling'),
        updated_by=data.get('updated_by'),
        vehicle_id=data.get('vehicle_id')
    )

    db.session.add(new_fueling)
    db.session.commit()

    return jsonify({'message': 'Fueling record added successfully'}), 201


# Get Fueling
@app.route('/api/fuelings', methods=['GET'])
@jwt_required()
def get_fuelings():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" or current_user.get("user_role") != "FUELING_PERSON":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    fuelings = Fueling.query.all()

    if fuelings:
        fuelings_list = [
            {
                "date_and_time": fueling.date_and_time,
                "fuel_amount": fueling.fuel_amount,
                "thecost": fueling.thecost,
                "proof_of_fueling": fueling.proof_of_fueling,
                "updated_by": fueling.updated_by,
                "vehicle_id": fueling.vehicle_id
            }
            for fueling in fuelings
        ]
        return jsonify(fuelings_list)
    else:
        return jsonify({"message": "No fueling records found"}), 404


# Update Fueling
@app.route('/api/fuelings/update/<int:fueling_id>', methods=['PUT'])
@jwt_required()
def update_fueling(fueling_id):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" and current_user.get("user_role") != "FUELING_PERSON":
        return jsonify({"message": "Unauthorized access. Admin or Fueling Person role required."}), 403

    fueling = Fueling.query.get(fueling_id)

    if not fueling:
        return jsonify({"message": "Fueling record not found"}), 404

    data = request.get_json()

    fueling.date_and_time = data.get('date_and_time', fueling.date_and_time)
    fueling.fuel_amount = data.get('fuel_amount', fueling.fuel_amount)
    fueling.thecost = data.get('thecost', fueling.thecost)
    fueling.proof_of_fueling = data.get('proof_of_fueling', fueling.proof_of_fueling)
    fueling.updated_by = data.get('updated_by', fueling.updated_by)
    fueling.vehicle_id = data.get('vehicle_id', fueling.vehicle_id)

    db.session.commit()

    return jsonify({'message': 'Fueling record updated successfully'}), 200


# Delete Fueling
@app.route('/api/fuelings/delete/<int:fueling_id>', methods=['DELETE'])
@jwt_required()
def delete_fueling(fueling_id):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" and current_user.get("user_role") != "FUELING_PERSON":
        return jsonify({"message": "Unauthorized access. Admin or Fueling Person role required."}), 403

    fueling = Fueling.query.get(fueling_id)

    if not fueling:
        return jsonify({"message": "Fueling record not found"}), 404

    db.session.delete(fueling)
    db.session.commit()

    return jsonify({'message': 'Fueling record deleted successfully'}), 200


# Add Route
@app.route('/api/routes/add', methods=['POST'])
@jwt_required()
def add_route():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    data = request.get_json()

    new_route = Route(
        route_id=data.get('route_id'),
        start_time=data.get('start_time'),
        end_time=data.get('end_time'),
        start_point_lang=data.get('start_point_lang'),
        start_point_lat=data.get('start_point_lat'),
        end_point_lang=data.get('end_point_lang'),
        end_point_lat=data.get('end_point_lat'),
        status=data.get('status'),
        thedate=data.get('thedate'),
        registered_by=data.get('registered_by')
    )

    db.session.add(new_route)
    db.session.commit()

    return jsonify({'message': 'Route added successfully'}), 201


# Get Route
@app.route('/api/routes', methods=['GET'])
@jwt_required()
def get_routes():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN" or current_user.get("user_role") != "DRIVER":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    routes = Route.query.all()

    if routes:
        routes_list = [
            {
                "route_id": route.route_id,
                "start_time": route.start_time,
                "end_time": route.end_time,
                "start_point_lang": route.start_point_lang,
                "start_point_lat": route.start_point_lat,
                "end_point_lang": route.end_point_lang,
                "end_point_lat": route.end_point_lat,
                "status": route.status,
                "thedate": route.thedate,
                "registered_by": route.registered_by
            }
            for route in routes
        ]
        return jsonify(routes_list)
    else:
        return jsonify({"message": "No routes found"}), 404
    

# Update Route
@app.route('/api/routes/update/<int:route_id>', methods=['PUT'])
@jwt_required()
def update_route(route_id):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    route = Route.query.get(route_id)

    if not route:
        return jsonify({"message": "Route not found"}), 404

    data = request.get_json()

    route.start_time = data.get('start_time', route.start_time)
    route.end_time = data.get('end_time', route.end_time)
    route.start_point_lang = data.get('start_point_lang', route.start_point_lang)
    route.start_point_lat = data.get('start_point_lat', route.start_point_lat)
    route.end_point_lang = data.get('end_point_lang', route.end_point_lang)
    route.end_point_lat = data.get('end_point_lat', route.end_point_lat)
    route.status = data.get('status', route.status)
    route.thedate = data.get('thedate', route.thedate)
    route.registered_by = data.get('registered_by', route.registered_by)

    db.session.commit()

    return jsonify({'message': 'Route updated successfully'}), 200


# Delete Route
@app.route('/api/routes/delete/<int:route_id>', methods=['DELETE'])
@jwt_required()
def delete_route(route_id):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    route = Route.query.get(route_id)

    if not route:
        return jsonify({"message": "Route not found"}), 404

    db.session.delete(route)
    db.session.commit()

    return jsonify({'message': 'Route deleted successfully'}), 200


# Add Task
@app.route('/api/tasks/add', methods=['POST'])
@jwt_required()
def add_task():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    data = request.get_json()

    new_task = Task(
        task_id=data.get('task_id'),
        created_by=data.get('created_by'),
        route_id=data.get('route_id'),
        driver_id=data.get('driver_id')
    )

    db.session.add(new_task)
    db.session.commit()

    return jsonify({'message': 'Task added successfully'}), 201


# Get Task
@app.route('/api/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    tasks = Task.query.all()

    if tasks:
        tasks_list = [
            {
                "task_id": task.task_id,
                "created_by": task.created_by,
                "route_id": task.route_id,
                "driver_id": task.driver_id
            }
            for task in tasks
        ]
        return jsonify(tasks_list)
    else:
        return jsonify({"message": "No tasks found"}), 404    
    

# Update Task
@app.route('/api/tasks/update/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    task = Task.query.get(task_id)

    if not task:
        return jsonify({"message": "Task not found"}), 404

    data = request.get_json()

    task.created_by = data.get('created_by', task.created_by)
    task.route_id = data.get('route_id', task.route_id)
    task.driver_id = data.get('driver_id', task.driver_id)

    db.session.commit()

    return jsonify({'message': 'Task updated successfully'}), 200


# Delete Task
@app.route('/api/tasks/delete/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    current_user = get_jwt_identity()

    if current_user.get("user_role") != "ADMIN":
        return jsonify({"message": "Unauthorized access. Admin role required."}), 403

    task = Task.query.get(task_id)

    if not task:
        return jsonify({"message": "Task not found"}), 404

    db.session.delete(task)
    db.session.commit()

    return jsonify({'message': 'Task deleted successfully'}), 200
    
    
if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", False))

