from flask import Flask, render_template, request, redirect, url_for
from crypto.rsa import generate_keys, encrypt_message, decrypt_message

app = Flask(__name__)

# Generate RSA keys (in a real app, these would be stored securely)
private_key, public_key = generate_keys()


@app.route('/')
def home():
    return redirect(url_for('send_message'))


@app.route('/send', methods=['GET', 'POST'])
def send_message():
    if request.method == 'POST':
        message = request.form['message']
        encrypted_message = encrypt_message(public_key, message)
        # Save or send encrypted message to the receiver
        # In a real app, you'd likely send it over a network connection
        return render_template('send.html', encrypted_message=encrypted_message)
    return render_template('send.html')


@app.route('/receive', methods=['GET', 'POST'])
def receive_message():
    if request.method == 'POST':
        encrypted_message = request.form['encrypted_message']
        decrypted_message = decrypt_message(private_key, bytes.fromhex(encrypted_message))
        return render_template('receive.html', decrypted_message=decrypted_message)
    return render_template('receive.html')


if __name__ == '__main__':
    app.run(debug=True)
