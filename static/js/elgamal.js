// =============== Receiver Functions ===============

// Function to display the received public key
function viewPublicKey() {
    fetch('/elgamal/get_public_key')
        .then(response => response.json())
        .then(data => {
            const publicKeyDisplay = document.getElementById("publicKeyDisplay");

            // Display the public key inside the div
            publicKeyDisplay.innerHTML = `<pre>${data.public_key}</pre>`;
            publicKeyDisplay.style.display = "block"; // Make the div visible
        })
        .catch(error => console.error("Error fetching public key:", error));
}

// Function to display the encrypted message
function viewEncryptedMessage() {
    fetch('/elgamal/receive_encrypted_message')
        .then(response => response.json())
        .then(data => {
            const encryptedMessageDisplay = document.getElementById("encryptedMessage");

            // Display the encrypted message inside the div
            if (data.encrypted_message) {
                encryptedMessageDisplay.innerHTML = `<pre>${data.encrypted_message}</pre>`;
                encryptedMessageDisplay.style.display = "block"; // Make the div visible
            } else {
                alert("No encrypted message found.");
            }
        })
        .catch(error => console.error("Error fetching encrypted message:", error));
}

// Function to decrypt the encrypted message
function decryptMessage() {
    const encryptedMessageDiv = document.getElementById("encryptedMessage");
    const encryptedMessage = encryptedMessageDiv.textContent.trim();

    if (!encryptedMessage) {
        alert("No encrypted message to decrypt.");
        return;
    }

    fetch('/elgamal/decrypt_message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encrypted_message: encryptedMessage })
    })
        .then(response => response.json())
        .then(data => {
            const decryptedMessageDisplay = document.getElementById("decryptedMessage");

            // Display the decrypted message inside the div
            if (data.decrypted_message) {
                decryptedMessageDisplay.innerHTML = `<pre>${data.decrypted_message}</pre>`;
                decryptedMessageDisplay.style.display = "block"; // Make the div visible
            } else {
                alert("Failed to decrypt the message.");
            }
        })
        .catch(error => console.error("Error decrypting message:", error));
}

// =============== Sender Functions ===============

// Function to generate keys and display the public key
function generateKeys() {
    fetch('/elgamal/generate_sender_keys', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            const publicKeyDisplay = document.getElementById("publicKeyDisplay");
            const publicKey = document.getElementById("publicKey");

            publicKey.innerText = data.public_key;
            publicKeyDisplay.style.display = "block"; // Show the public key box
        })
        .catch(error => console.error("Error generating keys:", error));
}

// Function to share the public key with the receiver
function shareKey() {
    const publicKey = document.getElementById("publicKey").innerText;

    fetch('/elgamal/share_key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ public_key: publicKey })
    })
        .then(() => {
            alert("Public key shared with the receiver.");
        })
        .catch(error => console.error("Error sharing public key:", error));
}

// Function to send an encrypted message
function sendMessage() {
    const message = document.getElementById("message").value;

    if (!message) {
        alert("Please enter a message to send.");
        return;
    }
