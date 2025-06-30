from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from pymongo import MongoClient
from datetime import datetime, timedelta
import pytz
import os
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging

# Configure logging to show debug messages
# In production, you might want to adjust this level to INFO or WARNING for less verbose logs.
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# IMPORTANT FOR DEPLOYMENT:
# 1. For production, set FLASK_SECRET_KEY as an environment variable in your deployment environment.
#    Example on Linux/macOS: export FLASK_SECRET_KEY='your_very_long_random_string_here_in_production'
#    Example for Heroku/Render: Set it in Config Vars
# 2. For local development, you can provide a fallback (e.g., os.urandom(24)) or ensure the env var is set.
#    os.urandom(24) generates a good random key.
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
# If you prefer to explicitly hardcode a temporary key for local dev (less secure but works, but REMOVE FOR DEPLOYMENT):
# app.secret_key = "a_super_secret_key_for_development_only_change_this"

# MongoDB Configuration
# These are loaded from environment variables. Provide sensible defaults for local development.
# Render will inject these environment variables when deployed.
DB_NAME = os.getenv("DB_NAME", "powerloom")
LOOM_DATA_COLLECTION = os.getenv("LOOM_DATA_COLLECTION", "loom_data")
USERS_COLLECTION = os.getenv("USERS_COLLECTION", "users")

# Timezone Configuration for Indian Standard Time (IST)
IST = pytz.timezone('Asia/Kolkata')

def get_db_connection():
    """Establish and return MongoDB connection, along with collections.
    Attempts to read MONGO_URI from environment variable first, then uses a fallback for local dev.
    """
    client = None
    try:
        # Load MONGO_URI from environment variable.
        # For local development, you can set it in your shell, or use a fallback here.
        # On Render, it WILL be set as an env var.
        mongo_uri = os.getenv("MONGO_URI")

        if not mongo_uri:
            app.logger.warning("MONGO_URI environment variable not set. Using hardcoded fallback for local development.")
            # FALLBACK FOR LOCAL DEVELOPMENT ONLY. REPLACE WITH YOUR ACTUAL LOCAL CONNECTION STRING IF DIFFERENT.
            # This URI should be the exact one from MongoDB Atlas for your cluster.
            mongo_uri = "mongodb+srv://gowthamst31:gowtham123@powerloom-cluster.gfl74dq.mongodb.net/?retryWrites=true&w=majority&appName=powerloom-cluster" #
            
        app.logger.debug(f"Attempting MongoDB connection with URI (first 30 chars): {mongo_uri[:30]}...")

        client = MongoClient(mongo_uri)
        db = client[DB_NAME]
        loom_collection = db[LOOM_DATA_COLLECTION]
        users_collection = db[USERS_COLLECTION]
        
        # Test the connection by sending a command to the database
        client.admin.command('ismaster')  
        app.logger.info(f"Successfully established MongoDB connection to DB '{DB_NAME}'.")
        app.logger.debug(f"Collections: Loom='{LOOM_DATA_COLLECTION}', Users='{USERS_COLLECTION}'")
        return client, db, loom_collection, users_collection
    except Exception as e:
        app.logger.error(f"MongoDB connection error: {str(e)}", exc_info=True)
        if client:
            client.close()
        return None, None, None, None

def handle_db_errors(f):
    """Decorator to handle database errors and ensure client closure."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client = None
        db = None
        loom_collection = None
        users_collection = None
        try:
            client, db, loom_collection, users_collection = get_db_connection()
            if client is None or db is None or loom_collection is None or users_collection is None:
                app.logger.critical("Failed to get database connection in decorator. Returning 503.")
                return jsonify({
                    'status': 'error',
                    'message': 'Database connection failed. Please try again later.'
                }), 503
            
            return f(client, db, loom_collection, users_collection, *args, **kwargs)
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
        return render_template("form.html", username=session.get('username'), role=session.get('role'))
    return redirect(url_for('login_page'))

@app.route("/login")
def login_page():
    """Renders the login HTML page."""
    return render_template("login.html")

@app.route("/authenticate", methods=["POST"])
@handle_db_errors
def authenticate(client, db, loom_collection, users_collection):
    """Authenticates user credentials."""
    data = request.form
    username_input = data.get('username')
    password_input = data.get('password')

    app.logger.info(f"Login attempt received for username: '{username_input}'")
    
    if not username_input or not password_input:
        app.logger.warning(f"Missing username or password for attempt: {username_input if username_input else 'N/A'}")
        return jsonify({'status': 'error', 'message': 'Username and password are required.'}), 400

    username_for_db = username_input.strip().lower() 
    app.logger.info(f"Querying DB for username (normalized): '{username_for_db}'")

    user = users_collection.find_one({"username": username_for_db})

    if user:
        app.logger.info(f"User '{username_for_db}' found in database. Role: {user.get('role')}.")
        if check_password_hash(user['password_hash'], password_input):
            session['logged_in'] = True
            session['username'] = user['username'] 
            session['role'] = user['role']
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
def add_user(client, db, loom_collection, users_collection):
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
            "created_at": datetime.utcnow()
        })
        app.logger.info(f"Admin '{session['username']}' successfully added new user: {username} ({role}).")
        return jsonify({'status': 'success', 'message': f'User {username} added successfully.'}), 201
    except Exception as e:
        app.logger.error(f"Failed to add user '{username}' by admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to add user due to an internal error.'}), 500

@app.route("/admin/remove_user", methods=["POST"])
@login_required
@admin_required
@handle_db_errors
def remove_user(client, db, loom_collection, users_collection):
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
            return jsonify({'status': 'success', 'message': f'User {username_to_remove} removed successfully.'}), 200
        else:
            app.logger.info(f"Admin '{session['username']}' attempted to remove user '{username_to_remove}', but user not found.")
            return jsonify({'status': 'error', 'message': 'User not found.'}), 404
    except Exception as e:
        app.logger.error(f"Failed to remove user '{username_to_remove}' by admin '{session['username']}': {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Failed to remove user due to an internal error.'}), 500

@app.route("/admin/get_users", methods=["GET"])
@login_required
@admin_required
@handle_db_errors
def get_users(client, db, loom_collection, users_collection):
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
def add_form(client, db, loom_collection, users_collection):
    """Handles submission of new loom production data."""
    data = request.form 
    
    # Initialize meters and salary_per_meter to None or a default value
    # This prevents NameError if an early return happens due to validation issues.
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

    # Explicitly get string values for numerical fields
    meters_str = data.get("meters")
    salary_per_meter_str = data.get("salary_per_meter")

    # Validate and convert meters
    try:
        meters = int(meters_str)
        if meters < 0:
            app.logger.warning(f"Negative meters value received from admin '{session['username']}': {meters_str}.")
            return jsonify({'status': 'error', 'message': 'Meters value cannot be negative.'}), 400
    except ValueError:
        app.logger.warning(f"Invalid meters format received from admin '{session['username']}': '{meters_str}'.")
        return jsonify({'status': 'error', 'message': 'Meters must be a valid number.'}), 400

    # Validate and convert salary_per_meter
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

        # Parse the date string to a naive datetime object at midnight
        date_obj_naive_midnight = datetime.strptime(raw_date_input, "%Y-%m-%d")
        app.logger.debug(f"Add Form: Naive datetime object at midnight: {date_obj_naive_midnight}")

        # Make it UTC-aware at UTC midnight for consistent storage
        # This is a common and robust way to store dates when only the day matters
        date_obj_utc = pytz.utc.localize(date_obj_naive_midnight)
        app.logger.debug(f"Add Form: Final UTC datetime to be stored: {date_obj_utc}")

    except ValueError:
        app.logger.warning(f"Invalid date format received from admin '{session['username']}': {data['date']}.")
        return jsonify({
            'status': 'error',
            'message': 'Invalid date format. Use THAT-MM-DD.'
        }), 400

    record = {
        "loomer_name": data["loomer_name"].strip().lower(),
        "loom_number": data["loom_number"].strip().lower(),
        "shift": data["shift"].strip().lower(),
        "meters": meters, # Now guaranteed to be defined
        "salary_per_meter": salary_per_meter, # Now guaranteed to be defined
        "date": date_obj_utc, # Store the UTC datetime object
        "created_at": datetime.utcnow()
    }

    try:
        result = loom_collection.insert_one(record)
        app.logger.info(f"Admin '{session['username']}' successfully added loom data: {record}.")
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
def get_meters(client, db, loom_collection, users_collection):
    """Handles requests to get total meters produced for a loomer within a date range and returns individual records."""
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
        # Localize from_date to IST and convert to UTC (beginning of the day in IST)
        from_date_utc = IST.localize(from_date_naive).astimezone(pytz.utc)
        app.logger.debug(f"Get Meters: Query 'from_date' (UTC): {from_date_utc}")
        
        to_date_naive = datetime.strptime(raw_to_date_input, "%Y-%m-%d")
        # Calculate midnight of the NEXT day in IST and then convert to UTC.
        # This correctly forms an inclusive range for the target day in IST.
        next_day_naive = to_date_naive + timedelta(days=1)
        to_date_ist_next_day_midnight = IST.localize(next_day_naive)
        to_date_utc = to_date_ist_next_day_midnight.astimezone(pytz.utc)
        app.logger.debug(f"Get Meters: Query 'to_date' (UTC - next day midnight): {to_date_utc}")


        if from_date_utc > to_date_utc:
            app.logger.warning(f"Invalid date range: From date {raw_from_date_input} is after To date {raw_to_date_input} from user '{session['username']}'.")
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
            "$lt": to_date_utc # Changed to $lt (less than) for next day's midnight
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

    if data["shift"].strip().lower() != "all":
        query["shift"] = data["shift"].strip().lower()

    if data["loom_number"].strip().lower() != "all":
        query["loom_number"] = data["loom_number"].strip().lower()

    print(f"\n--- Debugging get_meters ---") # Keep print for immediate console visibility
    print(f"Received form data: {data}")
    print(f"User role: {session.get('role')}, Username: {session.get('username')}")
    print(f"Parsed from_date (UTC for query): {from_date_utc}")
    print(f"Parsed to_date (UTC for query): {to_date_utc}")
    print(f"MongoDB query being executed: {query}")
    print(f"--- End Debugging ---\n")

    try:
        records = loom_collection.find(query, {"_id": 0})
        
        records_list = []
        total_meters = 0
        total_salary = 0.0

        for record in records:
            app.logger.debug(f"Get Meters: Raw record from DB: {record}")
            if 'date' in record and isinstance(record['date'], datetime):
                # Ensure the datetime object from MongoDB is timezone-aware UTC before conversion
                db_utc_date = record['date']
                if db_utc_date.tzinfo is None or db_utc_date.tzinfo.utcoffset(db_utc_date) is None:
                    db_utc_date = pytz.utc.localize(db_utc_date)
                
                ist_date = db_utc_date.astimezone(IST)
                app.logger.debug(f"Get Meters: Converted to IST for display: {ist_date}")
                record['date'] = ist_date.strftime("%a, %d-%m-%Y") 
                app.logger.debug(f"Get Meters: Formatted date string for display: {record['date']}")
            
            meters_val = record.get("meters", 0)
            salary_per_meter_val = record.get("salary_per_meter", 0.0)

            if isinstance(meters_val, (int, float)):
                total_meters += int(meters_val)
            
            if isinstance(salary_per_meter_val, (int, float)):
                total_salary += (int(meters_val) * float(salary_per_meter_val))

            record['salary_per_meter'] = f"{float(salary_per_meter_val):.2f}"
            
            records_list.append(record)
        
        app.logger.info(f"Report generated for {session['username']} (Role: {session['role']}): {total_meters} meters, {total_salary:.2f} salary across {len(records_list)} records.")
        return jsonify({
            'status': 'success',
            'total_meters': total_meters,
            'total_salary': f"{total_salary:.2f}",
            'record_count': len(records_list),
            'records': records_list,
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
def remove_data(client, db, loom_collection, users_collection):
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
            return jsonify({
                'status': 'success',
                'message': f'Successfully removed {result.deleted_count} records.'
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

if __name__ == "__main__":
    # IMPORTANT FOR DEPLOYMENT:
    # Set debug=False for production.
    # The built-in Flask server is NOT suitable for production.
    # Use a production WSGI server like Gunicorn instead (e.g., gunicorn wsgi:application).
    app.run(host='0.0.0.0', port=5000, debug=False) # Changed to debug=False for production readiness