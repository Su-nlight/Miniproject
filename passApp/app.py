# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.fernet import Fernet
import database
from twofa_esp import *


# Predefined encryption key (generated once and stored securely)
PREDEFINED_KEY = None
cipher_suite = None

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Initialize the database
database.init_db()
is_authenticated = False

@app.route('/')
def index():
    passwords = database.get_passwords()
    return render_template('index.html', passwords=passwords)

@app.route('/login', methods=['POST'])
async def login():
    global is_authenticated
    global PREDEFINED_KEY
    global cipher_suite
    password = request.form['password']
    print(password)
    response = await get_stored_encrypted_key(password)
    print(response)
    if response == None:
        flash("No key stored.")
    elif type(response) == dict:
        flash(response["Message"])
    elif type(response) == str:
        is_authenticated = True
        PREDEFINED_KEY = response
        cipher_suite = Fernet( PREDEFINED_KEY )
        flash('Successfully authenticated!', 'success')

    return redirect(url_for('index'))


@app.route('/add', methods=['POST'])
def add():
    global is_authenticated
    if not is_authenticated:
        flash('Please authenticate first!', 'error')
        return redirect(url_for('index'))

    name = request.form['name']
    username = request.form['username']
    password = request.form['password']

    # Encrypt the password
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    # Add the encrypted password to the database
    database.add_password(name, username, encrypted_password)
    flash('Password added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/retrieve', methods=['POST'])
def retrieve():
    global is_authenticated
    if not is_authenticated:
        flash('Please authenticate first!', 'error')
        return redirect(url_for('index'))

    name = request.form['name']
    data = database.get_password(name)

    if data is None:
        flash('Password not found!', 'error')
        return redirect(url_for('index'))

    decrypted_password = cipher_suite.decrypt(data.get("encrypted_password").encode()).decode()
    flash(f'Decrypted password for {name} (Username: {data["username"]}): {decrypted_password}', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
