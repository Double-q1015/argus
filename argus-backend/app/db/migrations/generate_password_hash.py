import bcrypt

def generate_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

if __name__ == "__main__":
    password = "admin123"
    hashed = generate_hash(password)
    print(f"Password: {password}")
    print(f"Hash: {hashed}") 