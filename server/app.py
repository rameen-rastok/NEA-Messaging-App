#=== Computer Science Non-Exam-Assessment A Level ===#
#=== Server Program for messaging application ===#

#=== Import relevant flask modules ===#
from flask import Flask, render_template, url_for, redirect, request, session, flash
from flask_socketio import SocketIO, send, emit, join_room, leave_room

#=== Import SQL Database and JSON files ===#
from flask_sqlalchemy import SQLAlchemy
import json

#=== Import hashing / encryption ===#
import uuid
import cryptography
from cryptography.fernet import Fernet
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#=== Create Flask App ===#
app = Flask(__name__)

#=== Set a Secret key for Security ===#
app.secret_key = uuid.uuid4().hex

#=== SQLite3 database setup through SQLAlchemy ===#
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///messages.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

#=== Generate Asymmetric Key ===#
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

#=== Creates/Loads Private Key ===#
with open("private_key.pem", "wb") as file:
    file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

#=== Creates/Loads Public Key ===#
with open("public_key.pem", "wb") as file:
    file.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

#=== Decrypts incoming messages from clients ===#
def decrypt_message(data):
    with open("private_key.pem", "rb") as private_key_file:
        use_private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)
        cdata = bytes.fromhex(data)
    decrypted_message = use_private_key.decrypt(
        cdata,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return decrypted_message.decode()


#=== Creates/Loads Database Encryption Key ===#
def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()

encryption_key = load_key()
cipher_suite = Fernet(encryption_key)

#=== Create Database ===#
database = SQLAlchemy(app)

#=== Create Database Table ===#
class Message(database.Model):
    #=== Primary Key ===#
    id = database.Column(database.Integer, primary_key=True)
    #=== Records ===#
    username = database.Column(database.String(100), nullable=False)
    room = database.Column(database.String(100), nullable=False)
    message = database.Column(database.Text, nullable=False)
    timestamp = database.Column(database.DateTime, default=datetime.utcnow)

    def __init__(self, username, room, message):
        self.username = username
        self.room = room
        #=== Message Encryption ===#
        self.message = cipher_suite.encrypt(message.encode()).decode()

    #=== Symmetric Decryption ===#
    def decrypt_message(self):
        return cipher_suite.decrypt(self.message.encode()).decode()

#=== Database Initialisation ===#
with app.app_context():
    database.create_all()

#=== Create SocketIO instance and initialise ===#
socketio = SocketIO()
socketio.init_app(app, cors_allowed_origins="*")

#=== Connected Users and Rooms and IDs ===#
active_users = {}
client_keys = {}
client_ids = {}

#=== Access Saved Server Name and Rooms ===#
def open_saved_files():
    try:
        # === Read save data from JSON format ===#
        with open('savedata.json', "r") as savefile:
            saved_data = json.load(savefile)

    #=== Create Save File if not Found ===#
    except FileNotFoundError:
        #=== Default Rooms ===#
        server_rooms = ["Room1", "Room2", "Room3", "Room4", "Room5", "Room6", "Room7", "Room8"]

        # === WebUI Login Key ===#
        login_key = str(uuid.uuid4().hex)[:16]

        #=== Write save data into JSON format ===#
        with open("savedata.json", "w") as savefile:
            server_info = {"server_name": "Unnamed Server", "server_rooms": server_rooms, "login_key": login_key}
            json.dumps(server_info, indent=4)
            json.dump(server_info, savefile)

#=== Handler for giving rooms to clients ===#
@app.route("/get_rooms")
def get_rooms():
    with open('savedata.json', "r") as savefile:
        saved_data = json.load(savefile)
        server_rooms = saved_data["server_rooms"]
    return {"rooms": server_rooms}

#=== Handler for giving server name ===#
@app.route("/get_name")
def get_name():
    with open('savedata.json', "r") as savefile:
        saved_data = json.load(savefile)
        server_name = saved_data["server_name"]
    return server_name

#=== Room Joining Handler ===#
@socketio.on("join_room")
def handle_join(data):
    with open('savedata.json', "r") as savefile:
        saved_data = json.load(savefile)
        server_name = saved_data["server_name"]
        server_rooms = saved_data["server_rooms"]
    #=== Get Client Data ===#
    username = data.get("username")
    room = data.get("room")
    client_public_key = data.get("client_public_key")
    socket_id = request.sid
    client_ids[username] = socket_id

    #=== Ignores Invalid Requests ===#
    if not username or not room:
        return

    if room not in server_rooms:
        print(f"Error, user {username} failed attempt to join non-existant room {room}.")
        return

    #=== Joining the Room ===#
    join_room(room)
    active_users[username] = room
    client_keys[username] = client_public_key
    print(f"{username} has joined the room: {room}")

    emit("room_message", f"{username} has joined the room.", room=room)

#=== Room Leaving Handler ===#
@socketio.on("leave_room")
def handle_leave(data):
    #=== Get Username and Room ===#
    username = data.get("username")
    room = active_users.get(username)

    #=== Ensures Valid Leaving ===#
    if room:
        leave_room(room)
        del active_users[username]
        del client_keys[username]
        print(f"{username} left room: {room}")

#=== Room Message Handler ===#
@socketio.on("send_message")
def handle_message(data):
    #=== Get Message Data ===#
    username = data["username"]
    room = data["room"]
    message = data["message"]
    decrypted_message = decrypt_message(message)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    #=== Store messages in database ===#
    store_message = Message(username=username, room=room, message=decrypted_message)
    database.session.add(store_message)
    database.session.commit()
    #=== Ensures messages are only sent to relevant rooms ===#
    print(f"[{room}]: {timestamp} : {username}: {decrypted_message}")

    for i in active_users:
        if active_users[i] == room:
            user_public_key = serialization.load_pem_public_key(client_keys[i].encode())
            encrypted_message = user_public_key.encrypt(
                decrypted_message.encode(),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            emit("receive_message", {"username": username, "message": encrypted_message, "timestamp": timestamp}, room=room, to=client_ids[i])

#=== Flask website render ===#
@app.route("/", methods=["GET", "POST"])
def index_page():
    #=== Check saved Data ===#
    with open('savedata.json', "r") as savefile:
        saved_data = json.load(savefile)
        server_name = saved_data["server_name"]
        server_rooms = saved_data["server_rooms"]
        login_key = saved_data["login_key"]

    #=== Check if login matches key ===#
    if request.method == "POST":
        if "login_submit_button" in request.form:
            attempted_key = request.form.get("login_key")
            if attempted_key == login_key:
                return redirect(url_for("config"))
            else:
                return render_template("login.html", server_name=server_name)
    else:
        return render_template("login.html", server_name=server_name)
    return render_template("login.html", server_name=server_name, server_rooms=server_rooms)

@app.route("/config", methods=["GET", "POST"])
def config():
    #=== Server Config Page ===#
    if request.method == "POST":
        print(request.form.get("server_name"))
        with open('savedata.json', "r") as savefile:
            saved_data = json.load(savefile)
            server_name = saved_data["server_name"]
            server_rooms = saved_data["server_rooms"]
            login_key = saved_data["login_key"]

        if "name_submit_button" in request.form:
            if request.form.get("server_name") != server_name:
                with open("savedata.json", "w") as savefile:
                    server_info = {"server_name": request.form.get("server_name"), "server_rooms": server_rooms, "login_key": login_key}
                    json.dump(server_info, savefile)
                    server_name = request.form.get("server_name")
        elif "room_submit_button" in request.form:
            new_rooms_data = request.form.get("server_room")
            new_rooms = new_rooms_data.split(",")
            with open("savedata.json", "w") as savefile:
                server_info = {"server_name": server_name, "server_rooms": new_rooms, "login_key": login_key}
                json.dump(server_info, savefile)
                server_rooms = new_rooms

    elif request.method == "GET":
        with open('savedata.json', "r") as savefile:
            saved_data = json.load(savefile)
            server_name = saved_data["server_name"]
            server_rooms = saved_data["server_rooms"]
            login_key = saved_data["login_key"]
        return render_template("index.html", server_name=server_name, server_rooms=server_rooms)
    else:
        with open('savedata.json', "r") as savefile:
            saved_data = json.load(savefile)
            server_name = saved_data["server_name"]
            server_rooms = saved_data["server_rooms"]
            login_key = saved_data["login_key"]
        return render_template("index.html", server_name=server_name, server_rooms=server_rooms)
    return render_template("index.html", server_name=server_name, server_rooms=server_rooms)

#=== Get Message History ===#
@socketio.on("get_history")
def get_message_history(data):
    room = data["room"]
    username = data["username"]
    #=== Searches Database ===#
    messages = Message.query.filter_by(room=room).all()
    #=== Returns Dictionary of Messages ===#
    history = [
            {"username": msg.username, "message": msg.decrypt_message(), "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
            for msg in messages
        ]
    user_public_key = serialization.load_pem_public_key(client_keys[username].encode())
    #=== Encrypt all Messages and Send as a List ===#
    for mesg in range(0, len(history)):
        encrypted_data = user_public_key.encrypt(
            history[mesg]["message"].encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        history[mesg]["message"] = encrypted_data
    emit("loading_history", history, room=room, to=client_ids[username])

#=== Get Public Key for Encryption ===#
@app.route("/get_public_key")
def get_public_key():
    with open("public_key.pem", "rb") as file:
        public_key_for_client = file.read().decode()
    return {"public_key": public_key_for_client}

#=== Main function ===#
if __name__ == "__main__":
    open_saved_files()
    with open('savedata.json', "r") as savefile:
        saved_data = json.load(savefile)
        login_key = saved_data["login_key"]
    _port = 5000
    _localip = "127.8.8.1"
    print(f"Login Key: {login_key}")
    print("Use this key to login to the WebUI config")
    print(f"Websocket on: {_localip}:{_port}")
    socketio.run(app, host=_localip, port=_port, debug=True, allow_unsafe_werkzeug=True)
    #=== Runs the server on dedicated socket and debug env ===#