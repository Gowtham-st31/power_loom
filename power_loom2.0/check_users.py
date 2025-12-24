from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from datetime import datetime
import os # Import os for potential environment variables, though not used in MONGO_URI directly here

# ✅ IMPORTANT: Ensure this MONGO_URI matches the one in app.py
# If you have your MongoDB Atlas URI stored securely as an environment variable, use that.
# For now, it's hardcoded as per your provided previous code.
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://gowthamst31:gowtham123@powerloom-cluster.gfl74dq.mongodb.net/?retryWrites=true&w=majority&appName=powerloom-cluster")


if not MONGO_URI:
    raise RuntimeError("MONGO_URI is not set")

DB_NAME = "powerloom"
USERS_COLLECTION = "users" # This is the collection where user data is stored

client = None

try:
    print(f"\n--- Attempting to connect to MongoDB to manage {DB_NAME}.{USERS_COLLECTION} ---")
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    users_collection = db[USERS_COLLECTION]

    # Test the connection to primary just to be sure
    client.admin.command('ismaster')
    print("✅ MongoDB connection successful.")

    admin_username = "admin"
    admin_password = "adminpass"  # This is the password you will use to log in
    
    # Hash the password using werkzeug.security
    hashed_password = generate_password_hash(admin_password)

    # Use update_one with upsert=True to either create the admin user or reset its password
    result = users_collection.update_one(
        {"username": admin_username}, # Query for the 'admin' user (ensure lowercase as per login logic)
        {
            "$set": { # Set or update these fields
                "password_hash": hashed_password,
                "role": "admin",
                "created_at": datetime.utcnow() # Record the creation/update time
            }
        },
        upsert=True # If the user doesn't exist, insert it. If it does, update it.
    )

    if result.upserted_id:
        print(f"✅ Admin user '{admin_username}' created with a new password.")
    elif result.modified_count > 0:
        print(f"🔁 Admin user '{admin_username}' found. Password has been reset/updated.")
    else:
        print(f"ℹ️ Admin user '{admin_username}' already exists and password was already up-to-date (no changes made).")


    print(f"\n🔑 Use these credentials to log in to the application:")
    print(f"   Username: {admin_username}")
    print(f"   Password: {admin_password}") # This is the plaintext password you type

except Exception as e:
    print(f"❌ Error during MongoDB operation in check_users.py: {e}")
    # Print the full traceback for more detailed debugging
    import traceback
    traceback.print_exc()
finally:
    if client:
        client.close()
        print("✅ MongoDB client connection closed.")

