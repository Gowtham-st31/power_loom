import os
import json
from datetime import datetime, timedelta, UTC # Import UTC for timezone-aware datetimes
import pytz
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from bson.objectid import ObjectId # Import ObjectId for MongoDB
import logging

# Import SocketIO
from flask_socketio import SocketIO, emit

# Import requests at the top level to ensure it's always available for AI API calls
import requests 

# Configure logging to show debug messages
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# IMPORTANT FOR DEPLOYMENT:
# 1. For production, set FLASK_SECRET_KEY as an environment variable in your deployment environment.
#    Example on Linux/macOS: export FLASK_SECRET_KEY='your_very_long_random_string_here_in_production'\
#    Example for Heroku/Render: Set it in Config Vars
# 2. For local development, os.urandom(24) generates a good random key.
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))

# Initialize SocketIO
# cors_allowed_origins="*" allows connections from any origin. Adjust for production security.
socketio = SocketIO(app, cors_allowed_origins="*")

# MongoDB Configuration
# These are loaded from environment variables. Provide sensible defaults for local development.
# Render will inject these environment variables when deployed.
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://gowthamst31:gowtham123@powerloom-cluster.gfl74dq.mongodb.net/?retryWrites=true&w=majority&appName=powerloom-cluster")
DB_NAME = os.getenv("DB_NAME", "powerloom")
LOOM_DATA_COLLECTION = os.getenv("LOOM_DATA_COLLECTION", "loom_data")
USERS_COLLECTION = os.getenv("USERS_COLLECTION", "users")
# New collections for Warp management
WARP_DATA_COLLECTION = os.getenv("WARP_DATA_COLLECTION", "warp_status")
WARP_HISTORY_COLLECTION = os.getenv("WARP_HISTORY_COLLECTION", "warp_history")


# Timezone Configuration for Indian Standard Time (IST)
IST = pytz.timezone('Asia/Kolkata')

# Configure the maximum number of detailed records to send to AI for analysis
# Be cautious when increasing this value, as it can lead to exceeding the AI model's context window
MAX_DETAILED_RECORDS_FOR_AI = 999999999999999999999999999999999999999


def get_db_connection():
    """Establish and return MongoDB connection, along with collections."""
    client = None
    try:
        app.logger.debug(f"Attempting MongoDB connection with URI (first 30 chars): {MONGO_URI[:30]}...")
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        loom_collection = db[LOOM_DATA_COLLECTION]
        users_collection = db[USERS_COLLECTION]
        warp_data_collection = db[WARP_DATA_COLLECTION] # New collection
        warp_history_collection = db[WARP_HISTORY_COLLECTION] # New collection
        
        # Test the connection by sending a command to the database
        # This command will raise an exception if connection fails or primary is not found
        ismaster_result = client.admin.command('ismaster')
        if not ismaster_result.get('ismaster'):
            raise Exception("MongoDB ismaster command failed: Not connected to a primary.")
        
        app.logger.info(f"Successfully established MongoDB connection to DB '{DB_NAME}'.")
        app.logger.debug(f"Collections: Loom='{LOOM_DATA_COLLECTION}', Users='{USERS_COLLECTION}', WarpData='{WARP_DATA_COLLECTION}', WarpHistory='{WARP_HISTORY_COLLECTION}'")
        return client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection
    except Exception as e:
        app.logger.error(f"MongoDB connection error during get_db_connection: {str(e)}", exc_info=True)
        if client:
            client.close()
        # Return None for all collections and client to signal failure
        return None, None, None, None, None, None

def handle_db_errors(f):
    """Decorator to handle database errors and ensure client closure."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client = None
        db = None
        loom_collection = None
        users_collection = None
        warp_data_collection = None # New
        warp_history_collection = None # New
        try:
            client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection = get_db_connection()
            if client is None or db is None or loom_collection is None or users_collection is None or warp_data_collection is None or warp_history_collection is None:
                app.logger.critical("Failed to get database connection in decorator. Returning 503.")
                return jsonify({
                    'status': 'error',
                    'message': 'Database connection failed. Please try again later.'
                }), 503
            
            return f(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection, *args, **kwargs)
        except Exception as e:
            app.logger.error(f"Database operation failed for route {request.path}: {str(e)}", exc_info=True)
            return jsonify({
                'status': 'error',
                'message': 'An internal database operation failed. Please try again.'
            }), 500
        finally:
            if client:
                client.close()
                app.logger.debug("MongoDB client connection closed.")
    return decorated_function

def login_required(f):
    """Decorator to check if user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            app.logger.warning(f"Unauthorized access attempt to {request.path}. User not logged in.")
            return jsonify({'status': 'error', 'message': 'Unauthorized. Please log in.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to check if user is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            app.logger.warning(f"Forbidden access attempt to {request.path}. User '{session.get('username', 'N/A')}' (Role: {session.get('role', 'N/A')}) is not an admin.")
            return jsonify({'status': 'error', 'message': 'Forbidden. Admin access required.'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---

@app.route("/")
def index():
    """Default route. Redirects to login page or home if already logged in."""
    if 'logged_in' in session and session['logged_in']:
        # Pass username and role to the template for display and conditional UI
        return render_template("form.html", username=session.get('username'), role=session.get('role'))
    return redirect(url_for('login_page'))

@app.route("/login")
def login_page():
    """Renders the login HTML page."""
    return render_template("login.html")

@app.route("/authenticate", methods=["POST"])
@handle_db_errors
def authenticate(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Authenticates user credentials."""
    data = request.form
    username_input = data.get('username')
    password = data.get('password')

    app.logger.info(f"Login attempt received for username: '{username_input}'")
    
    if not username_input or not password:
        app.logger.warning(f"Missing username or password for attempt: {username_input if username_input else 'N/A'}")
        return jsonify({'status': 'error', 'message': 'Username and password are required.'}), 400

    username_for_db = username_input.strip().lower() 
    app.logger.info(f"Querying DB for username (normalized): '{username_for_db}'")

    user = users_collection.find_one({"username": username_for_db})

    if user:
        app.logger.info(f"User '{username_for_db}' found in database. Role: {user.get('role')}.")
        if check_password_hash(user['password_hash'], password):
            session['logged_in'] = True
            session['username'] = user['username'] 
            session['role'] = user['role']
            session['user_id'] = str(user['_id']) # Store user_id for history logging
            app.logger.info(f"User '{username_input}' logged in successfully as '{user['role']}'.")
            return jsonify({'status': 'success', 'message': 'Login successful', 'role': user['role']}), 200
        else:
            app.logger.warning(f"Password mismatch for user: '{username_input}'.")
            return jsonify({'status': 'error', 'message': 'Invalid username or password.'}), 401
    else:
        app.logger.warning(f"User '{username_input}' (normalized to '{username_for_db}') not found in database.")
        return jsonify({'status': 'error', 'message': 'Invalid username or password.'}), 401

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    """Logs out the current user by clearing their session."""
    username = session.get('username', 'unknown')
    session.clear()
    app.logger.info(f"User '{username}' logged out successfully.")
    return jsonify({'status': 'success', 'message': 'Logged out successfully.'}), 200

# --- User Management (Admin Only) ---

@app.route("/admin/add_user", methods=["POST"])
@login_required
@admin_required
@handle_db_errors
def add_user(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Adds a new user (loomer or admin) to the system."""
    data = request.form
    username = data.get('username').strip().lower()
    password = data.get('password')
    role = data.get('role').strip().lower()

    if not username or not password or not role:
        app.logger.warning(f"Attempt to add user failed: Missing username, password, or role from admin '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'Username, password, and role are required.'}), 400
    
    if role not in ['admin', 'loomer']:
        app.logger.warning(f"Attempt to add user with invalid role '{role}' by admin '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'Role must be "admin" or "loomer".'}), 400

    if users_collection.find_one({"username": username}):
        app.logger.warning(f"Admin '{session['username']}' attempted to add existing user: {username}.")
        return jsonify({'status': 'error', 'message': 'User with this username already exists.'}), 409

    hashed_password = generate_password_hash(password)
    
    try:
        users_collection.insert_one({
            "username": username,
            "password_hash": hashed_password,
            "role": role,
            "created_at": datetime.now(UTC) # Ensured timezone-aware UTC
        })
        app.logger.info(f"Admin '{session['username']}' successfully added new user: {username} ({role}).")
        
        # Emit a SocketIO event to notify clients about user change
        socketio.emit('user_data_updated', {'message': f'User {username} added.'})
        
        return jsonify({'status': 'success', 'message': f'User {username} added successfully.'}), 201
    except Exception as e:
        app.logger.error(f"Failed to add user '{username}' by admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to add user due to an internal error.'}), 500

@app.route("/admin/update_password", methods=["POST"])
@login_required
@admin_required
@handle_db_errors
def update_password(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Allows an admin to update another user's password."""
    data = request.form
    username_to_update = data.get('username').strip().lower()
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not username_to_update or not new_password or not confirm_password:
        app.logger.warning(f"Admin '{session['username']}' attempted to update password with missing fields.")
        return jsonify({'status': 'error', 'message': 'Username, new password, and confirm password are required.'}), 400

    if new_password != confirm_password:
        app.logger.warning(f"Admin '{session['username']}' attempted to update password for '{username_to_update}', but passwords did not match.")
        return jsonify({'status': 'error', 'message': 'New password and confirm password do not match.'}), 400

    # Ensure admin cannot change their own password via this endpoint (should use a separate "change my password" feature if desired)
    if username_to_update == session['username']:
        app.logger.warning(f"Admin '{session['username']}' attempted to update their own password via this endpoint.")
        return jsonify({'status': 'error', 'message': 'You cannot update your own password using this tool. Please use a personal password change option if available.'}), 403

    user = users_collection.find_one({"username": username_to_update})
    if not user:
        app.logger.warning(f"Admin '{session['username']}' attempted to update password for non-existent user: {username_to_update}.")
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    hashed_password = generate_password_hash(new_password)

    try:
        users_collection.update_one(
            {"username": username_to_update},
            {"$set": {"password_hash": hashed_password}}
        )
        app.logger.info(f"Admin '{session['username']}' successfully updated password for user: {username_to_update}.")
        
        # Emit a SocketIO event to notify clients about user change
        socketio.emit('user_data_updated', {'message': f'Password for {username_to_update} updated.'})
        
        return jsonify({'status': 'success', 'message': f'Password for {username_to_update} updated successfully.'}), 200
    except Exception as e:
        app.logger.error(f"Failed to update password for user '{username_to_update}' by admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to update password due to an internal error.'}), 500


@app.route("/admin/remove_user", methods=["POST"])
@login_required
@admin_required
@handle_db_errors
def remove_user(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Removes a user by username from the system."""
    data = request.form
    username_to_remove = data.get('username').strip().lower()

    if not username_to_remove:
        return jsonify({'status': 'error', 'message': 'Username to remove is required.'}), 400
    
    if username_to_remove == session['username']:
        app.logger.warning(f"Admin '{session['username']}' attempted to remove their own account.")
        return jsonify({'status': 'error', 'message': 'You cannot remove your own admin account while logged in.'}), 403

    try:
        result = users_collection.delete_one({"username": username_to_remove})
        if result.deleted_count > 0:
            app.logger.info(f"Admin '{session['username']}' successfully removed user: {username_to_remove}.")
            # Emit a SocketIO event to notify clients about user change
            socketio.emit('user_data_updated', {'message': f'User {username_to_remove} removed.'})
            return jsonify({'status': 'success', 'message': f'User {username_to_remove} removed successfully.'}), 200
        else:
            app.logger.info(f"Admin '{session['username']}' attempted to remove user '{username_to_remove}', but user not found.")
            return jsonify({'status': 'info', 'message': 'No matching records found to remove.'}), 404
    except Exception as e:
        app.logger.error(f"Failed to remove user '{username_to_remove}' by admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to remove data due to an internal error.'}), 500

@app.route("/admin/get_users", methods=["GET"])
@login_required
@admin_required
@handle_db_errors
def get_users(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Retrieves a list of all users from the database, excluding sensitive fields."""
    try:
        users = users_collection.find({}, {"password_hash": 0, "created_at": 0}) 
        users_list = []
        for user in users:
            user['_id'] = str(user['_id']) 
            users_list.append(user)
        app.logger.info(f"Admin '{session['username']}' successfully fetched user list ({len(users_list)} users).")
        return jsonify({'status': 'success', 'users': users_list}), 200
    except Exception as e:
        app.logger.error(f"Failed to get users for admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to retrieve users due to an internal error.'}), 500

# --- Loom Data Management ---

@app.route("/add_form", methods=["POST"])
@login_required
@admin_required
@handle_db_errors
def add_form(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Handles submission of new loom production data, preventing duplicates."""
    data = request.form 
    
    meters = None 
    salary_per_meter = None

    required_fields = ["loomer_name", "loom_number", "shift", "meters", "salary_per_meter", "date"]
    for field in required_fields:
        if not data.get(field):
            app.logger.warning(f"Missing required field '{field}' during data addition by admin '{session['username']}'.")
            return jsonify({
                'status': 'error',
                'message': f'Missing required field: {field}'
            }), 400

    meters_str = data.get("meters")
    salary_per_meter_str = data.get("salary_per_meter")

    try:
        meters = int(meters_str)
        if meters < 0:
            app.logger.warning(f"Negative meters value received from admin '{session['username']}': {meters_str}.")
            return jsonify({'status': 'error', 'message': 'Meters value cannot be negative.'}), 400
    except ValueError:
        app.logger.warning(f"Invalid meters format received from admin '{session['username']}': '{meters_str}'.")
        return jsonify({'status': 'error', 'message': 'Meters must be a valid number.'}), 400

    try:
        salary_per_meter = float(salary_per_meter_str)
        if salary_per_meter < 0:
            app.logger.warning(f"Negative salary_per_meter value received from admin '{session['username']}': {salary_per_meter_str}.")
            return jsonify({'status': 'error', 'message': 'Salary per meter cannot be negative.'}), 400
    except ValueError:
        app.logger.warning(f"Invalid salary_per_meter format received from admin '{session['username']}': '{salary_per_meter_str}'.")
        return jsonify({'status': 'error', 'message': 'Salary per meter must be a valid number.'}), 400

    try:
        raw_date_input = data["date"]
        app.logger.debug(f"Add Form: Raw date input from form: {raw_date_input}")

        date_obj_naive_midnight = datetime.strptime(raw_date_input, "%Y-%m-%d")
        date_obj_utc = pytz.utc.localize(date_obj_naive_midnight).astimezone(pytz.utc)
        app.logger.debug(f"Add Form: Final UTC datetime to be stored: {date_obj_utc}")

    except ValueError:
        app.logger.warning(f"Invalid date format received from admin '{session['username']}': {data['date']}.")
        return jsonify({
            'status': 'error',
            'message': 'Invalid date format. Use THAT-MM-DD.'
        }), 400

    # --- Duplicate Data Check ---
    loomer_name = data["loomer_name"].strip().lower()
    loom_number = data["loom_number"].strip().lower()
    shift = data["shift"].strip().lower()

    duplicate_query = {
        "loomer_name": loomer_name,
        "loom_number": loom_number,
        "shift": shift,
        "date": date_obj_utc # Check against the UTC midnight date
    }
    
    existing_record = loom_collection.find_one(duplicate_query)
    if existing_record:
        app.logger.warning(f"Admin '{session['username']}' attempted to add duplicate record. Conflict with existing: {duplicate_query}.")
        return jsonify({
            'status': 'error',
            'message': 'A record for this Loomer, Loom Number, Shift, and Date already exists. Please update the existing record or choose a different date/shift.'
        }), 409 # Conflict status code

    record = {
        "loomer_name": loomer_name,
        "loom_number": loom_number,
        "shift": shift,
        "meters": meters, 
        "salary_per_meter": salary_per_meter, 
        "date": date_obj_utc, 
        "created_at": datetime.now(UTC) # Ensured timezone-aware UTC
    }

    try:
        result = loom_collection.insert_one(record)
        app.logger.info(f"Admin '{session['username']}' successfully added loom data: {record}.")
        
        # Emit a SocketIO event to notify clients about new data
        socketio.emit('new_loom_data', {'message': 'New loom data added!', 'record': str(result.inserted_id)})
        
        return jsonify({
            'status': 'success',
            'message': 'Data added successfully.',
            'inserted_id': str(result.inserted_id)
        }), 200
    except Exception as e:
        app.logger.error(f"Failed to insert loom data for admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to insert record due to an internal error.'
        }), 500

@app.route("/get_meters", methods=["POST"])
@login_required
@handle_db_errors
def get_meters(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """
    Handles requests to get total meters produced for a loomer within a date range
    and returns individual records, along along with subtotals per loom number.
    """
    data = request.form
    
    required_fields = ["loomer_name", "shift", "loom_number", "from_date", "to_date"]
    for field in required_fields:
        if not data.get(field):
            app.logger.warning(f"Missing required query field '{field}' from user '{session['username']}'.")
            return jsonify({
                'status': 'error',
                'message': f'Missing required field for report: {field}'
            }), 400

    try:
        raw_from_date_input = data["from_date"]
        raw_to_date_input = data["to_date"]
        app.logger.debug(f"Get Meters: Raw 'from' date input: {raw_from_date_input}")
        app.logger.debug(f"Get Meters: Raw 'to' date input: {raw_to_date_input}")

        from_date_naive = datetime.strptime(raw_from_date_input, "%Y-%m-%d")
        from_date_utc = IST.localize(from_date_naive).astimezone(pytz.utc)
        app.logger.debug(f"Get Meters: Query 'from_date' (UTC): {from_date_utc}")
        
        to_date_naive = datetime.strptime(raw_to_date_input, "%Y-%m-%d")
        next_day_naive = to_date_naive + timedelta(days=1)
        to_date_ist_next_day_midnight = IST.localize(next_day_naive)
        to_date_utc = to_date_ist_next_day_midnight.astimezone(pytz.utc)
        app.logger.debug(f"Get Meters: Query 'to_date' (UTC - next day midnight): {to_date_utc}")

        if from_date_utc >= to_date_utc:
            app.logger.warning(f"Invalid date range: From date {raw_from_date_input} is after or same as To date {raw_to_date_input} from user '{session['username']}'.")
            return jsonify({
                'status': 'error',
                'message': 'From Date cannot be after To Date.'
            }), 400

    except ValueError:
        app.logger.warning(f"Invalid date format for report query from user '{session['username']}': {data['from_date']} or {data['to_date']}.")
        return jsonify({
            'status': 'error',
            'message': 'Invalid date format for report. Use THAT-MM-DD.'
        }), 400

    query = {
        "date": {
            "$gte": from_date_utc,
            "$lt": to_date_utc 
        }
    }

    if session['role'] == 'loomer':
        query["loomer_name"] = session['username']
        app.logger.info(f"Loomer '{session['username']}' querying their own records for date range {raw_from_date_input} to {raw_to_date_input}.")
    else: # Admin user
        loomer_name_query = data["loomer_name"].strip().lower()
        if loomer_name_query != "all":
            query["loomer_name"] = loomer_name_query
        app.logger.info(f"Admin '{session['username']}' querying for loomer: '{loomer_name_query}' for date range {raw_from_date_input} to {raw_to_date_input}.")

    shift_query = data["shift"].strip().lower()
    if shift_query != "all":
        query["shift"] = shift_query

    loom_number_query = data["loom_number"].strip().lower()
    if loom_number_query != "all":
        query["loom_number"] = loom_number_query

    app.logger.debug(f"\n--- Debugging get_meters ---") # Keep debug for immediate console visibility
    app.logger.debug(f"Received form data: {data}")
    app.logger.debug(f"User role: {session.get('role')}, Username: {session.get('username')}")
    app.logger.debug(f"Parsed from_date (UTC for query): {from_date_utc}")
    app.logger.debug(f"Parsed to_date (UTC for query): {to_date_utc}")
    app.logger.debug(f"MongoDB query being executed: {query}")
    app.logger.debug(f"--- End Debugging ---\n")

    try:
        records_cursor = loom_collection.find(query, {"_id": 0})
        
        records_list = []
        total_meters = 0
        total_salary = 0.0
        loom_subtotals = {} # Dictionary to store subtotals per loom
        daily_subtotals = {} # Dictionary to store subtotals per day

        for record in records_cursor:
            app.logger.debug(f"Get Meters: Raw record from DB: {record}")
            
            # Store original UTC date for potential further processing (like daily subtotals)
            if 'date' in record and isinstance(record['date'], datetime):
                record['original_date_utc'] = record['date'] # Keep the datetime object
                db_utc_date = record['date']
                if db_utc_date.tzinfo is None or db_utc_date.tzinfo.utcoffset(db_utc_date) is None:
                    db_utc_date = pytz.utc.localize(db_utc_date)
                
                ist_date = db_utc_date.astimezone(IST)
                app.logger.debug(f"Get Meters: Converted to IST for display: {ist_date}")
                record['date_formatted'] = ist_date.strftime("%a, %d-%m-%Y") # Use a new key for formatted date
                app.logger.debug(f"Get Meters: Formatted date string for display: {record['date_formatted']}")
            
            meters_val = record.get("meters", 0)
            salary_per_meter_val = record.get("salary_per_meter", 0.0)

            if isinstance(meters_val, (int, float)):
                total_meters += int(meters_val)
            
            calculated_record_salary = (int(meters_val) * float(salary_per_meter_val))
            if isinstance(salary_per_meter_val, (int, float)):
                total_salary += calculated_record_salary

            record['calculated_salary'] = f"{calculated_record_salary:.2f}" # Add calculated salary to individual record
            record['salary_per_meter'] = f"{float(salary_per_meter_val):.2f}"
            
            records_list.append(record)

            # Always calculate loom subtotals for any query that returns records
            loom_num = record.get("loom_number", "N/A")
            if loom_num not in loom_subtotals:
                loom_subtotals[loom_num] = {"meters": 0, "salary": 0.0}
            loom_subtotals[loom_num]["meters"] += int(meters_val)
            loom_subtotals[loom_num]["salary"] += calculated_record_salary

            # Calculate daily subtotals if the date range is more than one day
            # Use the 'date_formatted' string as the key for daily subtotals
            day_label = record.get('date_formatted')
            if day_label:
                if day_label not in daily_subtotals:
                    daily_subtotals[day_label] = {"meters": 0, "salary": 0.0}
                daily_subtotals[day_label]["meters"] += int(meters_val)
                daily_subtotals[day_label]["salary"] += calculated_record_salary


        # Format loom_subtotals for JSON response
        formatted_loom_subtotals = []
        for loom, totals in loom_subtotals.items():
            formatted_loom_subtotals.append({
                "loom_number": loom,
                "total_meters": totals["meters"],
                "total_salary": f"{totals['salary']:.2f}"
            })
        
        # Format daily_subtotals for JSON response and sort by date
        formatted_daily_subtotals = []
        # Sort keys by parsing the date string back to datetime for accurate chronological order
        sorted_daily_subtotal_keys = sorted(daily_subtotals.keys(), key=lambda x: datetime.strptime(x, "%a, %d-%m-%Y"))

        for day_label in sorted_daily_subtotal_keys:
            totals = daily_subtotals[day_label]
            formatted_daily_subtotals.append({
                "date": day_label,
                "total_meters": totals["meters"],
                "total_salary": f"{totals['salary']:.2f}"
            })


        app.logger.info(f"Report generated for {session['username']} (Role: {session['role']}): {total_meters} meters, {total_salary:.2f} salary across {len(records_list)} records.")
        return jsonify({
            'status': 'success',
            'total_meters': total_meters,
            'total_salary': f"{total_salary:.2f}",
            'record_count': len(records_list),
            'records': records_list,
            'loom_subtotals': formatted_loom_subtotals, # Include loom subtotals
            'daily_subtotals': formatted_daily_subtotals, # Include daily subtotals
            'message': 'Report generated successfully.'
        }), 200
    except Exception as e:
        app.logger.error(f"Query failed for user '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to execute query due to an internal error.'
        }), 500

@app.route("/admin/remove_data", methods=["POST"])
@login_required
@admin_required
@handle_db_errors
def remove_data(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Removes loom data records based on provided criteria."""
    data = request.form
    
    loomer_name = data.get("loomer_name", "").strip().lower()
    loom_number = data.get("loom_number", "").strip().lower()
    shift = data.get("shift", "").strip().lower()
    from_date_str = data.get("from_date", "")
    to_date_str = data.get("to_date", "")

    delete_query = {}

    if loomer_name:
        delete_query["loomer_name"] = loomer_name
    if loom_number and loom_number != "all":
        delete_query["loom_number"] = loom_number
    if shift and shift != "all":
        delete_query["shift"] = shift
    
    if from_date_str and to_date_str:
        try:
            from_date = datetime.strptime(from_date_str, "%Y-%m-%d")
            from_date = IST.localize(from_date).astimezone(pytz.utc)
            to_date = datetime.strptime(to_date_str, "%Y-%m-%d")
            to_date = IST.localize(to_date).replace(hour=23, minute=59, second=59, microsecond=999999)
            to_date = to_date.astimezone(pytz.utc)

            if from_date > to_date:
                app.logger.warning(f"Invalid date range for data removal from admin '{session['username']}': {from_date_str} > {to_date_str}.")
                return jsonify({
                    'status': 'error',
                    'message': 'From Date cannot be after To Date for removal.'
                }), 400
            delete_query["date"] = {"$gte": from_date, "$lte": to_date}
        except ValueError:
            app.logger.warning(f"Invalid date format for data removal from admin '{session['username']}': {from_date_str} or {to_date_str}.")
            return jsonify({
                'status': 'error',
                'message': 'Invalid date format for removal. Use THAT-MM-DD.'
            }), 400
    elif from_date_str or to_date_str:
        app.logger.warning(f"Only one date provided for range removal from admin '{session['username']}'. Both required.")
        return jsonify({
            'status': 'error',
            'message': 'Both From Date and To Date are required for date-based removal.'
        }), 400

    if not loomer_name and not ("date" in delete_query):
        app.logger.warning(f"Admin '{session['username']}' attempted mass data removal without sufficient criteria.")
        return jsonify({
            'status': 'error',
            'message': 'At least Loomer Name or a Date Range is required to remove data. To remove all data for a specific loomer, enter their name and leave other fields as "all".'
        }), 400
    
    app.logger.info(f"Admin '{session['username']}' attempting to remove data with query: {delete_query}.")

    try:
        result = loom_collection.delete_many(delete_query)
        if result.deleted_count > 0:
            app.logger.info(f"Admin '{session['username']}' successfully removed {result.deleted_count} records matching {delete_query}.")
            # Emit a SocketIO event to notify clients about data change
            socketio.emit('loom_data_removed', {'message': f'{result.deleted_count} records removed.'})
            return jsonify({
                'status': 'success',
                'message': f'Successfully removed {result.deleted_count} records.',
                'deleted_count': result.deleted_count
            }), 200
        else:
            app.logger.info(f"Admin '{session['username']}' attempted to remove data, but no matching records found for query: {delete_query}.")
            return jsonify({
                'status': 'info',
                'message': 'No matching records found to remove.'
            }), 200
    except Exception as e:
        app.logger.error(f"Failed to remove data for admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to remove data due to an internal error.'
        }), 500

# Helper function to convert datetime objects in a dictionary/list to ISO format strings for JSON serialization
def convert_datetimes_to_iso(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: convert_datetimes_to_iso(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_datetimes_to_iso(elem) for elem in obj]
    return obj

# --- Graph Data Generation ---
@app.route("/get_graph_data", methods=["POST"])
@login_required
@handle_db_errors
def get_graph_data(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """
    Generates aggregated production data for graphs based on loomer, date range, and period (day, week, month, year).
    """
    data = request.form
    loomer_name_input = data.get('loomer_name', '').strip().lower()
    period = data.get('period', 'day').strip().lower()
    from_date_str = data.get('from_date')
    to_date_str = data.get('to_date')

    app.logger.debug(f"Graph data request: loomer='{loomer_name_input}', period='{period}', from='{from_date_str}', to='{to_date_str}'")

    if not from_date_str or not to_date_str:
        app.logger.warning(f"Missing date range for graph data from user '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'Both From Date and To Date are required for graphs.'}), 400

    try:
        from_date_naive = datetime.strptime(from_date_str, "%Y-%m-%d")
        from_date_utc = IST.localize(from_date_naive).astimezone(pytz.utc)
        
        to_date_naive = datetime.strptime(to_date_str, "%Y-%m-%d")
        # To make the 'to_date' inclusive up to the end of the day in IST,
        # we set it to the beginning of the next day in UTC.
        to_date_utc = IST.localize(to_date_naive + timedelta(days=1)).astimezone(pytz.utc)

        if from_date_utc >= to_date_utc:
            app.logger.warning(f"Invalid date range for graph data from user '{session['username']}': From date {from_date_str} is after or same as To date {to_date_str}.")
            return jsonify({'status': 'error', 'message': 'From Date must be before To Date.'}), 400

    except ValueError:
        app.logger.warning(f"Invalid date format for graph query from user '{session['username']}': {from_date_str} or {to_date_str}.")
        return jsonify({'status': 'error', 'message': 'Invalid date format. Use THAT-MM-DD.'}), 400

    match_query = {
        "date": {
            "$gte": from_date_utc,
            "$lt": to_date_utc
        }
    }

    if session['role'] == 'loomer':
        match_query["loomer_name"] = session['username']
        app.logger.info(f"Loomer '{session['username']}' querying their own graph data for period '{period}'.")
    elif loomer_name_input != "all":
        match_query["loomer_name"] = loomer_name_input
        app.logger.info(f"Admin '{session['username']}' querying graph data for loomer: '{loomer_name_input}' for period '{period}'.")
    else:
        app.logger.info(f"Admin '{session['username']}' querying graph data for all loomers for period '{period}'.")

    group_id = {}
    date_format = ""
    date_from_parts_config = {}

    if period == 'day':
        group_id = {
            "year": {"$year": "$date"},
            "month": {"$month": "$date"},
            "day": {"$dayOfMonth": "$date"}
        }
        date_format = "%Y-%m-%d"
        date_from_parts_config = {
            "year": "$_id.year",
            "month": "$_id.month",
            "day": "$_id.day",
            "hour": 0, "minute": 0, "second": 0, "millisecond": 0
        }
    elif period == 'week':
        group_id = {
            "isoWeekYear": {"$isoWeekYear": "$date"},
            "isoWeek": {"$isoWeek": "$date"}
        }
        date_format = "%G-W%V" # ISO Week Year - Week Number (e.g., 2023-W01)
        date_from_parts_config = {
            "isoWeekYear": "$_id.isoWeekYear",
            "isoWeek": "$_id.isoWeek",
            "isoDayOfWeek": 1, # Monday
            "hour": 0, "minute": 0, "second": 0, "millisecond": 0
        }
    elif period == 'month':
        group_id = {
            "year": {"$year": "$date"},
            "month": {"$month": "$date"}
        }
        date_format = "%Y-%m" # Example: 2024-07
        date_from_parts_config = {
            "year": "$_id.year",
            "month": "$_id.month",
            "day": 1,
            "hour": 0, "minute": 0, "second": 0, "millisecond": 0
        }
    elif period == 'year':
        group_id = {
            "year": {"$year": "$date"}
        }
        date_format = "%Y" # Example: 2024
        date_from_parts_config = {
            "year": "$_id.year",
            "month": 1, "day": 1,
            "hour": 0, "minute": 0, "second": 0, "millisecond": 0
        }
    else:
        app.logger.warning(f"Invalid period '{period}' for graph data from user '{session['username']}'. Defaulting to 'day'.")
        return jsonify({'status': 'error', 'message': 'Invalid period specified. Choose from day, week, month, year.'}), 400

    pipeline = [
        {"$match": match_query},
        {"$group": {
            "_id": group_id,
            "total_meters": {"$sum": "$meters"},
            "total_salary": {"$sum": {"$multiply": ["$meters", "$salary_per_meter"]}}
        }},
        {"$addFields": {
            "date_obj": {
                "$dateFromParts": {
                    **date_from_parts_config,
                    "timezone": "+0530" # IST offset for correct grouping/sorting, then convert to UTC for consistent storage
                }
            }
        }},
        {"$sort": {"date_obj": 1}}, # Sort by the actual date object
        {"$project": {
            "_id": 0,
            "label": {
                "$dateToString": {
                    "format": date_format,
                    "date": "$date_obj",
                    "timezone": "+0530" # Format in IST
                }
            },
            "meters": "$total_meters",
            "salary": {"$round": ["$total_salary", 2]}
        }}
    ]

    # Apply the helper function to make the pipeline JSON serializable for logging
    pipeline_for_logging = convert_datetimes_to_iso(pipeline)
    app.logger.debug(f"MongoDB Aggregation Pipeline for graph: {json.dumps(pipeline_for_logging, indent=2)}")

    try:
        results = list(loom_collection.aggregate(pipeline))
        
        labels = []
        meters_data = []
        salary_data = []

        for res in results:
            labels.append(res['label'])
            meters_data.append(res['meters'])
            salary_data.append(res['salary'])
        
        app.logger.debug(f"MongoDB Aggregation Results for graph: {json.dumps(results, indent=2)}") # Pretty print results
        app.logger.info(f"Graph data generated for user '{session['username']}' ({period} period) with {len(labels)} data points.")
        return jsonify({
            'status': 'success',
            'graph_data': {
                'labels': labels,
                'meters': meters_data,
                'salary': salary_data
            },
            'message': 'Graph data generated successfully.'
        }), 200
    except Exception as e:
        app.logger.error(f"Failed to generate graph data for user '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve graph data due to an internal error.'
        }), 500

@app.route("/analyze_report_with_ai", methods=["POST"])
@login_required
@admin_required
@handle_db_errors
def analyze_report_with_ai(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """
    Analyzes loom production report data using the Gemini AI and returns insights.
    Stores query and summary in session for follow-up questions.
    """
    data = request.form
    loomer_name_input = data.get('loomer_name', '').strip().lower()
    from_date_str = data.get('from_date')
    to_date_str = data.get('to_date')
    shift_query = data.get('shift', '').strip().lower()
    loom_number_query = data.get('loom_number', '').strip().lower()

    if not from_date_str or not to_date_str:
        app.logger.warning(f"Missing date range for AI analysis from admin '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'Both From Date and To Date are required for AI analysis.'}), 400

    try:
        from_date_naive = datetime.strptime(from_date_str, "%Y-%m-%d")
        from_date_utc = IST.localize(from_date_naive).astimezone(pytz.utc)
        
        to_date_naive = datetime.strptime(to_date_str, "%Y-%m-%d")
        next_day_naive = to_date_naive + timedelta(days=1)
        to_date_ist_next_day_midnight = IST.localize(next_day_naive)
        to_date_utc = to_date_ist_next_day_midnight.astimezone(pytz.utc)

        if from_date_utc > to_date_utc:
            app.logger.warning(f"Invalid date range for AI analysis from admin '{session['username']}': {from_date_str} is after To date {to_date_str}.")
            return jsonify({'status': 'error', 'message': 'From Date cannot be after To Date for AI analysis.'}), 400

    except ValueError:
        app.logger.warning(f"Invalid date format for AI analysis from admin '{session['username']}': {from_date_str} or {to_date_str}.")
        return jsonify({'status': 'error', 'message': 'Invalid date format for AI analysis. Use THAT-MM-DD.'}), 400

    # Construct query to fetch data for AI analysis
    query = {
        "date": {
            "$gte": from_date_utc,
            "$lt": to_date_utc 
        }
    }

    if loomer_name_input and loomer_name_input != "all":
        query["loomer_name"] = loomer_name_input
    if shift_query and shift_query != "all":
        query["shift"] = shift_query
    if loom_number_query and loom_number_query != "all":
        query["loom_number"] = loom_number_query

    app.logger.info(f"Admin '{session['username']}' requesting AI analysis for query: {query}.")

    try:
        records = list(loom_collection.find(query, {"_id": 0}))
        
        total_meters = sum(record.get("meters", 0) for record in records)
        total_salary = sum(record.get("meters", 0) * record.get("salary_per_meter", 0.0) for record in records)

        if not records:
            # Clear previous AI analysis session data if no records found
            session.pop('last_ai_analysis_query', None)
            session.pop('last_report_summary', None)
            return jsonify({'status': 'info', 'message': 'No data found for the selected criteria to analyze.'}), 200

        # Prepare data for AI prompt
        report_summary = {
            "total_meters_produced": total_meters,
            "total_salary_paid": f"{total_salary:.2f}",
            "number_of_records": len(records),
            "date_range": f"{from_date_str} to {to_date_str}",
            "loomer_filter": loomer_name_input if loomer_name_input else "All Loomers",
            "shift_filter": shift_query if shift_query else "All Shifts",
            "loom_number_filter": loom_number_query if loom_number_query else "All Loom Numbers"
        }
        
        # Store query parameters and report summary in session for follow-up questions
        # Convert datetime objects in query to string for session serialization
        session['last_ai_analysis_query'] = convert_datetimes_to_iso(query) 
        session['last_report_summary'] = report_summary


        # Limit detailed records sent to AI for the initial prompt to avoid exceeding context window
        detailed_records_for_ai = []
        for i, record in enumerate(records):
            if i >= MAX_DETAILED_RECORDS_FOR_AI: # Use the configurable limit
                break
            # Apply the convert_datetimes_to_iso helper function to each record copy
            processed_record = convert_datetimes_to_iso(record.copy())
            detailed_records_for_ai.append(processed_record)

        prompt_text = f"""
        Analyze the following powerloom production data and provide insights, trends, and potential areas for improvement.
        
        Overall Summary:
        {json.dumps(report_summary, indent=2)}

        Sample Detailed Records (up to {MAX_DETAILED_RECORDS_FOR_AI} records):
        {json.dumps(detailed_records_for_ai, indent=2)}

        Based on this data, please provide:
        1.  Key observations (e.g., peak production days/shifts, high/low performers).
        2.  Any noticeable trends or patterns.
        3.  Suggestions for improving efficiency or profitability.
        4.  Potential issues or anomalies.
        """
        
        app.logger.debug(f"Sending prompt to AI:\n{prompt_text[:999999999999999]}...") # Log first 500 chars

        # Call Gemini API
        api_key = "AIzaSyDABptEJ0hUgQMNHep7cAaLKADJXP8AL0w" 
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt_text}]}]
        }

        headers = {'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status() 
        
        ai_result = response.json()
        
        if ai_result.get('candidates') and ai_result['candidates'][0].get('content') and ai_result['candidates'][0]['content'].get('parts'): 
            ai_analysis = ai_result['candidates'][0]['content']['parts'][0]['text']
            app.logger.info(f"AI analysis successfully generated for admin '{session['username']}'.")
            return jsonify({
                'status': 'success',
                'ai_analysis': ai_analysis,
                'message': 'AI analysis generated successfully.'
            }), 200
        else:
            app.logger.error(f"AI response structure unexpected or missing content for AI analysis: {ai_result}")
            return jsonify({'status': 'error', 'message': 'Failed to get AI analysis: Unexpected AI response format.'}), 500

    except requests.exceptions.RequestException as req_e:
        app.logger.error(f"HTTP request to AI API failed for AI analysis from admin '{session['username']}': {str(req_e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to get AI analysis: Network or API error. Details: {str(req_e)}'}), 500
    except Exception as e:
        app.logger.error(f"Failed to perform AI analysis for admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to get AI analysis due to an internal server error.'}), 500


@app.route("/analyze_report_with_ai/ask_question", methods=["POST"])
@login_required
@admin_required
@handle_db_errors
def ask_ai_question(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """
    Handles follow-up questions to the AI based on the last generated report.
    """
    user_question = request.form.get('question')

    if not user_question:
        app.logger.warning(f"Empty follow-up question from admin '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'Please enter a question.'}), 400

    last_ai_analysis_query_raw = session.get('last_ai_analysis_query')
    last_report_summary = session.get('last_report_summary')

    if not last_ai_analysis_query_raw or not last_report_summary:
        app.logger.warning(f"No previous AI analysis context found for admin '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'No previous report analysis found. Please generate a report analysis first.'}), 400

    # Re-create datetime objects from ISO strings for MongoDB query
    last_ai_analysis_query = last_ai_analysis_query_raw.copy()
    if 'date' in last_ai_analysis_query and isinstance(last_ai_analysis_query['date'], dict):
        if '$gte' in last_ai_analysis_query['date']:
            last_ai_analysis_query['date']['$gte'] = datetime.fromisoformat(last_ai_analysis_query['date']['$gte'])
        if '$lt' in last_ai_analysis_query['date']:
            last_ai_analysis_query['date']['$lt'] = datetime.fromisoformat(last_ai_analysis_query['date']['$lt'])

    app.logger.info(f"Admin '{session['username']}' asking follow-up question: '{user_question}' based on query: {last_ai_analysis_query}.")

    try:
        # Re-fetch records using the stored query
        records = list(loom_collection.find(last_ai_analysis_query, {"_id": 0}))

        if not records:
            return jsonify({'status': 'info', 'message': 'No data found for the original criteria to answer the question.'}), 200

        # Prepare detailed records for AI, again respecting the limit
        detailed_records_for_ai = []
        for i, record in enumerate(records):
            if i >= MAX_DETAILED_RECORDS_FOR_AI:
                break
            processed_record = convert_datetimes_to_iso(record.copy())
            detailed_records_for_ai.append(processed_record)

        # Construct the follow-up prompt
        follow_up_prompt_text = f"""
        Here is a summary and sample data from a powerloom production report you previously analyzed:

        Overall Summary:
        {json.dumps(last_report_summary, indent=2)}

        Sample Detailed Records (up to {MAX_DETAILED_RECORDS_FOR_AI} records):
        {json.dumps(detailed_records_for_ai, indent=2)}

        Based on this information and your previous analysis, please answer the following question:
        "{user_question}"
        """

        app.logger.debug(f"Sending follow-up prompt to AI:\n{follow_up_prompt_text[:500]}...")

        # Call Gemini API
        api_key = "AIzaSyDABptEJ0hUgQMNHep7cAaLKADJXP8AL0w" 
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        payload = {
            "contents": [{"role": "user", "parts": [{"text": follow_up_prompt_text}]}]
        }

        headers = {'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status() 
        
        ai_result = response.json()

        if ai_result.get('candidates') and ai_result['candidates'][0].get('content') and ai_result['candidates'][0]['content'].get('parts'): 
            ai_answer = ai_result['candidates'][0]['content']['parts'][0]['text']
            app.logger.info(f"AI successfully answered follow-up question for admin '{session['username']}'.")
            return jsonify({
                'status': 'success',
                'ai_answer': ai_answer,
                'message': 'AI answered successfully.'
            }), 200
        else:
            app.logger.error(f"AI response structure unexpected or missing content for follow-up: {ai_result}")
            return jsonify({'status': 'error', 'message': 'Failed to get AI answer: Unexpected AI response format.'}), 500

    except requests.exceptions.RequestException as req_e:
        app.logger.error(f"HTTP request to AI API failed for follow-up question from admin '{session['username']}': {str(req_e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to get AI answer: Network or API error. Details: {str(req_e)}'}), 500
    except Exception as e:
        app.logger.error(f"Failed to answer follow-up question for admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to get AI answer due to an internal server error.'}), 500


@app.route("/admin/suggest_loomer_name", methods=["POST"])
@login_required
@admin_required
def suggest_loomer_name():
    """
    Generates a suggested loomer name using the Gemini AI.
    """
    app.logger.info(f"Admin '{session['username']}' requesting loomer name suggestion.")
    
    prompt_text = "Suggest a single, common, and appropriate name for a person who operates a powerloom machine. The name should be short and suitable for a username."

    try:
        api_key = "AIzaSyDABptEJ0hUgQMNHep7cAaLKADJXP8AL0w" 
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
        
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt_text}]}],
            "generationConfig": {
                "responseMimeType": "text/plain" # Expect plain text response
            }
        }

        headers = {'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status() 
        
        ai_result = response.json()
        
        if ai_result.get('candidates') and ai_result['candidates'][0].get('content') and ai_result['candidates'][0]['content'].get('parts'):
            suggested_name = ai_result['candidates'][0]['content']['parts'][0]['text'].strip()
            app.logger.info(f"AI successfully suggested loomer name: '{suggested_name}'.")
            return jsonify({
                'status': 'success',
                'suggested_name': suggested_name,
                'message': 'Loomer name suggested successfully.'
            }), 200
        else:
            app.logger.error(f"AI response structure unexpected or missing content for name suggestion: {ai_result}")
            return jsonify({'status': 'error', 'message': 'Failed to get AI name suggestion: Unexpected AI response format.'}), 500

    except requests.exceptions.RequestException as req_e:
        app.logger.error(f"HTTP request to AI API failed for name suggestion from admin '{session['username']}': {str(req_e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to get AI name suggestion: Network or API error. Details: {str(req_e)}'}), 500
    except Exception as e:
        app.logger.error(f"Failed to perform AI name suggestion for admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to get AI name suggestion due to an internal server error.'}), 500

# --- NEW WARP MANAGEMENT ROUTES ---

@app.route('/get_current_warp', methods=['GET'])
@login_required
@handle_db_errors
def get_current_warp(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Retrieves the current total warp value."""
    try:
        warp_doc = warp_data_collection.find_one({"_id": "current_warp"})
        total_warp = warp_doc['total_warp'] if warp_doc else 0.0
        app.logger.info(f"User '{session['username']}' fetched current warp: {total_warp}.")
        return jsonify({'status': 'success', 'total_warp': total_warp}), 200
    except Exception as e:
        app.logger.error(f"Failed to get current warp for user '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to retrieve current warp due to an internal error.'}), 500

@app.route('/update_warp', methods=['POST'])
@login_required
@admin_required # Only admin can update total warp
@handle_db_errors
def update_warp(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Updates the total warp value and logs the change."""
    data = request.get_json()
    value_change = float(data.get('value', 0))
    remarks = data.get('remarks', '').strip()
    date_str = data.get('date') # Get date from request

    if not isinstance(value_change, (int, float)):
        return jsonify({'status': 'error', 'message': 'Invalid value for warp change.'}), 400

    try:
        # Atomically update the total_warp
        # Use upsert=True to create the document if it's not exist
        result = warp_data_collection.find_one_and_update(
            {"_id": "current_warp"},
            {"$inc": {"total_warp": value_change}},
            upsert=True,
            return_document=True # Return the updated document
        )
        new_total_warp = result['total_warp'] if result else value_change # If upserted, result will be the new doc

        # Log to history
        warp_history_collection.insert_one({
            "timestamp": datetime.now(UTC), # Ensured timezone-aware UTC
            "user_id": session.get('user_id'),
            "username": session.get('username'),
            "change_type": "Update",
            "value_change": value_change,
            "new_total_warp": new_total_warp,
            "remarks": remarks,
            "date": datetime.strptime(date_str, '%Y-%m-%d') if date_str else datetime.now(UTC) # Ensured timezone-aware UTC
        })
        app.logger.info(f"Admin '{session['username']}' updated warp by {value_change}. New total: {new_total_warp}.")
        
        # Emit a SocketIO event to notify clients about warp change
        socketio.emit('warp_data_updated', {'message': 'Warp data updated!', 'new_total_warp': new_total_warp})
        
        return jsonify({'status': 'success', 'message': 'Warp updated successfully!', 'new_total_warp': new_total_warp}), 200
    except Exception as e:
        app.logger.error(f"Failed to update warp for admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to update warp due to an internal error.'}), 500

@app.route('/apply_knotting', methods=['POST'])
@login_required
@admin_required # Still only admin can use this calculation feature
def apply_knotting(): # Removed client, db, collections parameters as they are not needed for this calculation
    """
    Calculates the 'Current Total Warp - Entered Knotting Count' and returns it.
    It does NOT alter the total warp or store history.
    """
    data = request.get_json()
    knotting_value = float(data.get('knotting_value', 0))
    current_total_warp = float(data.get('current_total_warp', 0)) # Expect current_total_warp from frontend

    if not isinstance(knotting_value, (int, float)) or knotting_value < 0:
        return jsonify({'status': 'error', 'message': 'Knotting value must be a non-negative number.'}), 400
    
    if not isinstance(current_total_warp, (int, float)):
        return jsonify({'status': 'error', 'message': 'Current total warp must be a valid number.'}), 400

    calculated_remaining_warp = current_total_warp - knotting_value

    app.logger.info(f"Admin '{session['username']}' calculated knotting: {current_total_warp} - {knotting_value} = {calculated_remaining_warp}.")
    # No emit here as this is a calculation, not a data change in DB.
    return jsonify({
        'status': 'success',
        'message': 'Knotting calculation successful!',
        'calculated_remaining_warp': calculated_remaining_warp
    }), 200

@app.route('/get_warp_history', methods=['GET'])
@login_required
@handle_db_errors
def get_warp_history(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Retrieves the history of warp updates."""
    try:
        # Fetch history records, sorted by timestamp descending
        history_records = warp_history_collection.find().sort("timestamp", -1).limit(100) # Limit to 100 for recent history
        
        history_data = []
        for record in history_records:
            # Convert ObjectId to string for JSON serialization
            record['_id'] = str(record['_id'])
            
            # Format the 'timestamp' (when the record was created)
            if 'timestamp' in record and isinstance(record['timestamp'], datetime):
                ist_timestamp = pytz.utc.localize(record['timestamp']).astimezone(IST)
                record['record_timestamp_formatted'] = ist_timestamp.strftime("%Y-%m-%d %H:%M:%S") # Add time for clarity
            else:
                record['record_timestamp_formatted'] = 'N/A' # Fallback

            # Format the 'date' field (the date selected by the user for the event)
            if 'date' in record and isinstance(record['date'], datetime):
                # The 'date' stored in DB is already UTC midnight for the selected date.
                # Convert it to IST for display.
                ist_event_date = pytz.utc.localize(record['date']).astimezone(IST)
                record['event_date_formatted'] = ist_event_date.strftime("%Y-%m-%d") # Format as YYYY-MM-DD
            else:
                record['event_date_formatted'] = 'N/A' # Fallback

            # Ensure value_change and new_total_warp are floats for consistent display
            record['value_change'] = float(record.get('value_change', 0.0))
            record['new_total_warp'] = float(record.get('new_total_warp', 0.0))

            # Only include relevant fields for the frontend
            history_data.append({
                '_id': record['_id'],
                'record_timestamp': record['record_timestamp_formatted'], # When the record was created
                'event_date': record['event_date_formatted'],             # The date the user selected for the event
                'user_id': record.get('user_id'),
                'username': record.get('username'),
                'change_type': record.get('change_type'),
                'value_change': record['value_change'],
                'new_total_warp': record['new_total_warp'],
                'remarks': record.get('remarks', '')
            })
        
        app.logger.info(f"User '{session['username']}' fetched warp history ({len(history_data)} records).")
        return jsonify({'status': 'success', 'history': history_data}), 200
    except Exception as e:
        app.logger.error(f"Failed to get warp history for user '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to retrieve warp history due to an internal error.'}), 500


@app.route('/clear_warp_history', methods=['POST'])
@login_required
@admin_required # Only admin can clear warp history
@handle_db_errors
def clear_warp_history(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """Clears all warp history records."""
    try:
        result = warp_history_collection.delete_many({})
        app.logger.info(f"Admin '{session['username']}' cleared {result.deleted_count} warp history records.")
        
        # Emit a SocketIO event to notify clients about history cleared
        socketio.emit('warp_history_cleared', {'message': 'Warp history cleared!'})
        
        return jsonify({'status': 'success', 'message': f"{result.deleted_count} history records cleared successfully!"}), 200
    except Exception as e:
        app.logger.error(f"Failed to clear warp history for admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to clear warp history due to an internal error.'}), 500


# --- NEW GRAPH DATA ROUTES ---

@app.route("/get_meters_per_loom", methods=["POST"])
@login_required
@handle_db_errors
def get_meters_per_loom(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """
    Generates aggregated meters per loom number for a given date range.
    """
    data = request.form
    from_date_str = data.get('from_date')
    to_date_str = data.get('to_date')

    if not from_date_str or not to_date_str:
        app.logger.warning(f"Missing date range for meters per loom graph from user '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'Both From Date and To Date are required.'}), 400

    try:
        from_date_naive = datetime.strptime(from_date_str, "%Y-%m-%d")
        from_date_utc = IST.localize(from_date_naive).astimezone(pytz.utc)
        
        to_date_naive = datetime.strptime(to_date_str, "%Y-%m-%d")
        to_date_utc = IST.localize(to_date_naive + timedelta(days=1)).astimezone(pytz.utc)

        if from_date_utc >= to_date_utc:
            app.logger.warning(f"Invalid date range for meters per loom graph from user '{session['username']}': From date {from_date_str} is after or same as To date {to_date_str}.")
            return jsonify({'status': 'error', 'message': 'From Date must be before To Date.'}), 400

    except ValueError:
        app.logger.warning(f"Invalid date format for meters per loom graph from user '{session['username']}': {from_date_str} or {to_date_str}.")
        return jsonify({'status': 'error', 'message': 'Invalid date format. Use THAT-MM-DD.'}), 400

    match_query = {
        "date": {
            "$gte": from_date_utc,
            "$lt": to_date_utc
        }
    }

    # If a loomer is logged in, restrict to their data
    if session['role'] == 'loomer':
        match_query["loomer_name"] = session['username']
        app.logger.info(f"Loomer '{session['username']}' querying meters per loom.")
    else:
        app.logger.info(f"Admin '{session['username']}' querying meters per loom for all loomers.")

    pipeline = [
        {"$match": match_query},
        {"$group": {
            "_id": "$loom_number",
            "total_meters": {"$sum": "$meters"}
        }},
        {"$sort": {"_id": 1}}, # Sort by loom number
        {"$project": {
            "_id": 0,
            "loom_number": "$_id",
            "meters": "$total_meters"
        }}
    ]

    pipeline_for_logging = convert_datetimes_to_iso(pipeline)
    app.logger.debug(f"MongoDB Aggregation Pipeline for meters per loom: {json.dumps(pipeline_for_logging, indent=2)}")

    try:
        results = list(loom_collection.aggregate(pipeline))
        
        labels = [res['loom_number'] for res in results]
        meters_data = [res['meters'] for res in results]
        
        app.logger.info(f"Meters per loom data generated for user '{session['username']}' with {len(labels)} data points.")
        return jsonify({
            'status': 'success',
            'graph_data': {
                'labels': labels,
                'meters': meters_data
            },
            'message': 'Meters per loom data generated successfully.'
        }), 200
    except Exception as e:
        app.logger.error(f"Failed to generate meters per loom data for user '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve meters per loom data due to an internal error.'
        }), 500

@app.route("/get_meters_per_shift", methods=["POST"])
@login_required
@handle_db_errors
def get_meters_per_shift(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """
    Generates aggregated meters per shift for a given date range.
    """
    data = request.form
    from_date_str = data.get('from_date')
    to_date_str = data.get('to_date')

    if not from_date_str or not to_date_str:
        app.logger.warning(f"Missing date range for meters per shift graph from user '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'Both From Date and To Date are required.'}), 400

    try:
        from_date_naive = datetime.strptime(from_date_str, "%Y-%m-%d")
        from_date_utc = IST.localize(from_date_naive).astimezone(pytz.utc)
        
        to_date_naive = datetime.strptime(to_date_str, "%Y-%m-%d")
        to_date_utc = IST.localize(to_date_naive + timedelta(days=1)).astimezone(pytz.utc)

        if from_date_utc >= to_date_utc:
            app.logger.warning(f"Invalid date range for meters per shift graph from user '{session['username']}': From date {from_date_str} is after or same as To date {to_date_str}.")
            return jsonify({'status': 'error', 'message': 'From Date must be before To Date.'}), 400

    except ValueError:
        app.logger.warning(f"Invalid date format for meters per shift graph from user '{session['username']}': {from_date_str} or {to_date_str}.")
        return jsonify({'status': 'error', 'message': 'Invalid date format. Use THAT-MM-DD.'}), 400

    match_query = {
        "date": {
            "$gte": from_date_utc,
            "$lt": to_date_utc
        }
    }

    # If a loomer is logged in, restrict to their data
    if session['role'] == 'loomer':
        match_query["loomer_name"] = session['username']
        app.logger.info(f"Loomer '{session['username']}' querying meters per shift.")
    else:
        app.logger.info(f"Admin '{session['username']}' querying meters per shift for all loomers.")

    pipeline = [
        {"$match": match_query},
        {"$group": {
            "_id": "$shift",
            "total_meters": {"$sum": "$meters"}
        }},
        {"$sort": {"_id": 1}}, # Sort by shift name
        {"$project": {
            "_id": 0,
            "shift": "$_id",
            "meters": "$total_meters"
        }}
    ]

    pipeline_for_logging = convert_datetimes_to_iso(pipeline)
    app.logger.debug(f"MongoDB Aggregation Pipeline for meters per shift: {json.dumps(pipeline_for_logging, indent=2)}")

    try:
        results = list(loom_collection.aggregate(pipeline))
        
        labels = [res['shift'] for res in results]
        meters_data = [res['meters'] for res in results]
        
        app.logger.info(f"Meters per shift data generated for user '{session['username']}' with {len(labels)} data points.")
        return jsonify({
            'status': 'success',
            'graph_data': {
                'labels': labels,
                'meters': meters_data
            },
            'message': 'Meters per shift data generated successfully.'
        }), 200
    except Exception as e:
        app.logger.error(f"Failed to generate meters per shift data for user '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve meters per shift data due to an internal error.'
        }), 500
@app.route("/debug_session")
def debug_session():
    return jsonify(dict(session))

@app.route("/get_top_loomers", methods=["POST"])
@login_required
@handle_db_errors
def get_top_loomers(client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection):
    """
    Generates aggregated meters for top N loomers over a given date range.
    """
    data = request.form
    from_date_str = data.get('from_date')
    to_date_str = data.get('to_date')
    limit = int(data.get('limit', 5)) # Default to top 5

    if not from_date_str or not to_date_str:
        app.logger.warning(f"Missing date range for top loomers graph from user '{session['username']}'.")
        return jsonify({'status': 'error', 'message': 'Both From Date and To Date are required.'}), 400

    try:
        from_date_naive = datetime.strptime(from_date_str, "%Y-%m-%d")
        from_date_utc = IST.localize(from_date_naive).astimezone(pytz.utc)
        
        to_date_naive = datetime.strptime(to_date_str, "%Y-%m-%d")
        to_date_utc = IST.localize(to_date_naive + timedelta(days=1)).astimezone(pytz.utc)

        if from_date_utc >= to_date_utc:
            app.logger.warning(f"Invalid date range for top loomers graph from user '{session['username']}': From date {from_date_str} is after or same as To date {to_date_str}.")
            return jsonify({'status': 'error', 'message': 'From Date must be before To Date.'}), 400

    except ValueError:
        app.logger.warning(f"Invalid date format for top loomers graph from user '{session['username']}': {from_date_str} or {to_date_str}.")
        return jsonify({'status': 'error', 'message': 'Invalid date format. Use THAT-MM-DD.'}), 400

    match_query = {
        "date": {
            "$gte": from_date_utc,
            "$lt": to_date_utc
        }
    }

    # This graph is typically for admin to see all loomers' performance.
    # If a loomer is logged in, they can only see their own data (though "top loomers" is less meaningful for one person).
    if session['role'] == 'loomer':
        match_query["loomer_name"] = session['username']
        app.logger.info(f"Loomer '{session['username']}' querying top loomers (restricted to self).")
    else:
        app.logger.info(f"Admin '{session['username']}' querying top {limit} loomers.")

    pipeline = [
        {"$match": match_query},
        {"$group": {
            "_id": "$loomer_name",
            "total_meters": {"$sum": "$meters"}
        }},
        {"$sort": {"total_meters": -1}}, # Sort by total meters descending
        {"$limit": limit}, # Limit to top N
        {"$project": {
            "_id": 0,
            "loomer_name": "$_id",
            "meters": "$total_meters"
        }}
    ]

    pipeline_for_logging = convert_datetimes_to_iso(pipeline)
    app.logger.debug(f"MongoDB Aggregation Pipeline for top loomers: {json.dumps(pipeline_for_logging, indent=2)}")

    try:
        results = list(loom_collection.aggregate(pipeline))
        
        labels = [res['loomer_name'] for res in results]
        meters_data = [res['meters'] for res in results]
        
        app.logger.info(f"Top {limit} loomers data generated for user '{session['username']}' with {len(labels)} data points.")
        return jsonify({
            'status': 'success',
            'graph_data': {
                'labels': labels,
                'meters': meters_data
            },
            'message': 'Top loomers data generated successfully.'
        }), 200
    except Exception as e:
        app.logger.error(f"Failed to generate top loomers data for user '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve top loomers data due to an internal error.'
        }), 500

# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    app.logger.info('Client connected to SocketIO!')
    # Optionally, send initial data to the newly connected client
    # This might involve calling some of the get_graph_data or get_current_warp functions
    # but needs to be careful about session context (which isn't available directly in socketio events)
    # For now, we'll rely on the frontend explicitly requesting data after connection.

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info('Client disconnected from SocketIO.')

# You can add more specific SocketIO event handlers if needed for complex real-time interactions

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Render sets PORT env variable
    # Initial check for admin user. If no users exist, create a default admin.
    client, db, loom_collection, users_collection, warp_data_collection, warp_history_collection = get_db_connection()
    if client and users_collection is not None: 
        if users_collection.count_documents({}) == 0:
            app.logger.info("No users found. Creating default admin user.")
            default_admin_username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
            default_admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "adminpass") # CHANGE THIS IN PRODUCTION!

            hashed_password = generate_password_hash(default_admin_password)
            users_collection.insert_one({
                "username": default_admin_username,
                "password_hash": hashed_password,
                "role": "admin",
                "created_at": datetime.now(UTC) # Ensured timezone-aware UTC
            })
            app.logger.info(f"Default admin user '{default_admin_username}' created. PLEASE CHANGE THE DEFAULT PASSWORD IN PRODUCTION!")
        
        # Initialize current warp if it doesn't exist
        if warp_data_collection.find_one({"_id": "current_warp"}) is None:
            warp_data_collection.insert_one({"_id": "current_warp", "total_warp": 0.0})
            app.logger.info("Initialized 'current_warp' document in warp_status collection to 0.0.")

        client.close()
    else:
        app.logger.critical("Could not connect to database at startup to check/create default admin and initialize warp data.")

    # Run the app with SocketIO
    # Use host='0.0.0.0' for external access (e.g., in a Docker container or cloud deployment)
    # Use allow_unsafe_werkzeug=True for development only, not production
    socketio.run(app, debug=True, host='0.0.0.0', port=int(os.environ.get("PORT", 8080)), allow_unsafe_werkzeug=True)   
