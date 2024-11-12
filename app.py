from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = Flask(__name__)

# Store RSA keys and messages
sender_keys = {}
receiver_keys = {}
encrypted_message = None


@app.route('/RSA/sender')
def sender():
    return render_template('send.html')


@app.route('/RSA/receiver')
def receiver():
    return render_template('receive.html')


@app.route('/RSA/generate_sender_keys', methods=['POST'])
def generate_sender_keys():
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
def share_key():
    data = request.json
    receiver_keys['public'] = serialization.load_pem_public_key(data['public_key'].encode())
    return jsonify({"status": "Receiver's public key received"})


@app.route('/RSA/send_message', methods=['POST'])
def send_message():
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
def receive_encrypted_message():
    if encrypted_message:
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode()
        return jsonify({"encrypted_message": encrypted_message_b64})
    else:
        return jsonify({"error": "No message found"})


@app.route('/RSA/get_public_key', methods=['GET'])
def get_public_key():
    return jsonify({"public_key": sender_keys['public'].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()})


@app.route('/RSA/decrypt_message', methods=['POST'])
def decrypt_message():
    data = request.json
    encrypted_message_b64 = data.get('encrypted_message')
    encrypted_message = base64.b64decode(encrypted_message_b64)
    decrypted_message = sender_keys['private'].decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()
    return jsonify({"decrypted_message": decrypted_message})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
