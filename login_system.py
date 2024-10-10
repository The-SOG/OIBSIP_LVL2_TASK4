import bcrypt
import os

# Path to store user data
USER_DATA_FILE = "user_data.txt"

# Helper function to save user data (username:password_hash)
def save_user_data(username, hashed_password):
    with open(USER_DATA_FILE, "a") as f:
        f.write(f"{username}:{hashed_password.decode()}\n")

# Helper function to check if a user exists
def user_exists(username):
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE, "r") as f:
        users = f.readlines()
        for user in users:
            stored_username, _ = user.strip().split(":")
            if stored_username == username:
                return True
    return False

# Helper function to authenticate user
def authenticate_user(username, password):
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE, "r") as f:
        users = f.readlines()
        for user in users:
            stored_username, stored_password_hash = user.strip().split(":")
            if stored_username == username:
                return bcrypt.checkpw(password.encode(), stored_password_hash.encode())
    return False

# Register function
def register():
    print("\n--- Register ---")
    username = input("Enter username: ").strip()

    # Check if the username already exists
    if user_exists(username):
        print("Username already exists. Try another one.")
        return

    password = input("Enter password: ").strip()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    
    save_user_data(username, hashed_password)
    print("Registration successful!")

# Login function
def login():
    print("\n--- Login ---")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    if authenticate_user(username, password):
        print("Login successful!")
        access_secure_page(username)
    else:
        print("Invalid username or password!")

# Access secured page
def access_secure_page(username):
    print(f"\n--- Welcome to the Secured Page, {username} ---")
    print("Here is your secure content. Only logged-in users can see this!\n")

# Main Menu
def main():
    while True:
        print("\n--- Simple Authentication System ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option (1/2/3): ").strip()

        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
