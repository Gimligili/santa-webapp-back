import string
import secrets

def generate_pepper(length=32):
    characters = string.ascii_letters + string.digits + string.punctuation.replace(" ", "")
    return ''.join(secrets.choice(characters) for _ in range(length))

pepper = generate_pepper()
print(f"Generated pepper: {pepper}")
