from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# Step 1: Generate RSA Keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Step 2: Encrypt a message using the RSA public key
def encrypt_message(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message.encode('utf-8'))
    return encrypted_message

# Step 3: Decrypt the message using the RSA private key
def decrypt_message(encrypted_message, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
    return decrypted_message

# Example Usage
if __name__ == "__main__":
    # Generate RSA key pair
    private_key, public_key = generate_rsa_keys()

    print("RSA Public Key:")
    print(public_key.decode())
    print("\nRSA Private Key:")
    print(private_key.decode())

    # User input
    user_message = input("\nEnter the message you want to encrypt: ")

    # Encrypt the user's message
    encrypted_message = encrypt_message(user_message, public_key)
    print("\nEncrypted Message (in bytes):")
    print(encrypted_message)

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, private_key)
    print("\nDecrypted Message:")
    print(decrypted_message)
