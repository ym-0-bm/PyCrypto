from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = Flask(__name__)

# Store keys and messages
sender_keys = {}
receiver_keys = {}
encrypted_message = None


@app.route('/RSA/sender')
def rsa_sender():
    return render_template('send.html')


@app.route('/RSA/receiver')
def rsa_receiver():
    return render_template('receive.html')


@app.route('/RSA/generate_sender_keys', methods=['POST'])
def generate_sender_keys_rsa():
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        sender_keys['private'] = private_key
        sender_keys['public'] = public_key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return jsonify({"public_key": public_pem.decode()})

    except Exception as e:
        print("Error generating keys:", e)
        return jsonify({"error": "Failed to generate keys"}), 500


@app.route('/RSA/share_key', methods=['POST'])
def share_key_rsa():
    data = request.json
    receiver_keys['public'] = serialization.load_pem_public_key(data['public_key'].encode())
    return jsonify({"status": "Receiver's public key received"})


@app.route('/RSA/send_message', methods=['POST'])
def send_message_rsa():
    global encrypted_message
    data = request.json
    message = data['message']
    encrypted_message = receiver_keys['public'].encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
    return jsonify({"encrypted_message": encrypted_message_b64})


@app.route('/RSA/receive_encrypted_message', methods=['GET'])
def receive_encrypted_message_rsa():
    if encrypted_message:
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
        return jsonify({"encrypted_message": encrypted_message_b64})
    else:
        return jsonify({"error": "No message found"})


@app.route('/RSA/get_public_key', methods=['GET'])
def get_public_key_rsa():
    return jsonify({"public_key": sender_keys['public'].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()})


@app.route('/RSA/decrypt_message', methods=['POST'])
def decrypt_message_rsa():
    data = request.json
    encrypted_message_b64 = data.get('encrypted_message')
    encrypted_message = base64.b64decode(encrypted_message_b64)
    decrypted_message = sender_keys['private'].decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()
    return jsonify({"decrypted_message": decrypted_message})


@app.route('/elgamal/sender')
def elgamal_sender():
    return render_template('send_elgamal.html')


@app.route('/elgamal/receiver')
def elgamal_receiver():
    return render_template('receive_elgamal.html')


@app.route('/elgamal/generate_sender_keys', methods=['POST'])
def generate_sender_keys_elgamal():
    try:
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        sender_keys['private'] = private_key
        sender_keys['public'] = public_key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return jsonify({"public_key": public_pem.decode()})
    except Exception as e:
        print("Error generating keys:", e)
        return jsonify({"error": "Failed to generate keys"}), 500


@app.route('/elgamal/share_key', methods=['POST'])
def share_key_elgamal():
    data = request.json
    receiver_keys['public'] = serialization.load_pem_public_key(data['public_key'].encode())
    return jsonify({"status": "Receiver's public key received"})


@app.route('/elgamal/send_message', methods=['POST'])
def send_message_elgamal():
    global encrypted_message
    data = request.json
    message = data['message'].encode()
    # ElGamal encryption would occur here using receiver's public key.
    # Example placeholder for encryption.
    encrypted_message = message  # Replace with real encryption
    encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
    return jsonify({"encrypted_message": encrypted_message_b64})


@app.route('/elgamal/receive_encrypted_message', methods=['GET'])
def receive_encrypted_message_elgamal():
    if encrypted_message:
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
        return jsonify({"encrypted_message": encrypted_message_b64})
    else:
        return jsonify({"error": "No message found"})


@app.route('/elgamal/get_public_key', methods=['GET'])
def get_public_key_elgamal():
    return jsonify({"public_key": sender_keys['public'].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()})


@app.route('/elgamal/decrypt_message', methods=['POST'])
def decrypt_message_elgamal():
    data = request.json
    encrypted_message_b64 = data.get('encrypted_message')
    encrypted_message = base64.b64decode(encrypted_message_b64)
    # ElGamal decryption would occur here using sender's private key.
    # Example placeholder for decryption.
    decrypted_message = encrypted_message.decode()  # Replace with real decryption
    return jsonify({"decrypted_message": decrypted_message})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
