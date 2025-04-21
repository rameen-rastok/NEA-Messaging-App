#=== Computer Science Non-Exam-Assessment A Level ===#
#=== Client Program for messaging application ===#

#=== Module Imports for GUI ===#
from kivy.app import App
from kivy.core.window import Window
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.widget import Widget
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.relativelayout import RelativeLayout
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.settings import SettingsWithSidebar
from kivy.network.urlrequest import UrlRequest
from kivy.properties import ObjectProperty
from kivy.properties import StringProperty
from kivy.uix.popup import Popup
from kivy.lang import Builder
from kivy.utils import get_color_from_hex
from kivy.clock import Clock
from textwrap import fill
from kivy import Config

#===Module imports for save data  ===#
import configparser
from kivy.storage.jsonstore import JsonStore

#=== Module imports for  Server ===#
from socketio import Client
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import websocket

#=== Flask-SocketIO client ===#
sio = Client()

#=== A Configuration setting to avoid red dots on right click ===#
Config.set('input', 'mouse', 'mouse,multitouch_on_demand')

#=== GUI test - Scrollable messages ===#
class ScrollableMessages(ScrollView):
    def __init__(self, **kwargs):
        super().__init__(*kwargs)
        #=== Set Scroll Settings ===#
        self.scroll_x = 0
        self.scroll_y = 1
        self.size_hint_y = 0.9

        #=== Embedded Box Layout ===#
        self.emb_box = BoxLayout(orientation="vertical", size_hint_y=None)
        self.add_widget(self.emb_box)

        #=== Message receiving handler ===#
        @sio.on("receive_message")
        def on_message(data):
            #=== Adds message to the GUI ===#
            Clock.schedule_once(lambda dt: add_message_to_ui(data), 0)

        #=== History receiving handler ===#
        @sio.on("loading_history")
        def on_history(data):
            #=== Adds message to the GUI ===#
            Clock.schedule_once(lambda dt: history_load(data), 0)

        #=== Offloads GUI to the main thread ===#
        def add_message_to_ui(data):
            username = data["username"]
            message = data["message"]
            timestamp = data["timestamp"]

            decrypted_message = decrypt_message(message)

            new_message = MessageContainer(username, decrypted_message, timestamp)
            self.emb_box.add_widget(new_message)

            #=== Keeps scroll at the bottom ===#
            self.emb_box.height += new_message.height
            Clock.schedule_once(lambda dt: setattr(self, "scroll_y", 0), 0)

        # === Offloads GUI to the main thread ===#
        def history_load(data):

            self.clear_messages()
            message_history = data
            for mesg in range(0, len(message_history)):
                messages={"username": message_history[mesg]["username"], "message": message_history[mesg]["message"], "timestamp": message_history[mesg]["timestamp"]}
                add_message_to_ui(messages)

    #=== Clears Message Chain ===#
    def clear_messages(self):
        self.emb_box.clear_widgets()
        self.emb_box.height = 0

#=== GUI test - Message Box ===#
class MessageContainer(BoxLayout):
    def __init__(self, usernames, message_text, timestamp, **kwargs):
        super().__init__(**kwargs)

        #=== Creating Message Box ===#
        self.orientation = "horizontal"
        self.size_hint_y = None
        self.height = 30
        self.padding = [8, 4]

        #=== Label for text ===#
        namelabel = Label(text=usernames, size_hint_y=0.5, color=App.get_running_app().data_store.get("settings")["text_colour"])
        timelabel = Label(text=timestamp, size_hint_y=0.5, color=App.get_running_app().data_store.get("settings")["text_colour"])
        self.horizontal_box = BoxLayout(orientation="horizontal", size_hint_x=0.5)
        textlabel = Label(text=message_text, size_hint_x=0.8, color=App.get_running_app().data_store.get("settings")["text_colour"])
        self.horizontal_box.add_widget(namelabel)
        self.horizontal_box.add_widget(timelabel)
        self.add_widget(self.horizontal_box)
        self.add_widget(textlabel)

#=== GUI test - Messaging Menu ===#
class MessagingMenu(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(*kwargs)

        #=== Add Menu Button and Room Name ===#
        self.menu_box = BoxLayout(orientation="horizontal", size_hint_y="0.1")
        room_button = Button(text="Back", background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                             color=App.get_running_app().data_store.get("settings")["text_colour"])
        room_button.bind(on_press=lambda instance: App.get_running_app().change_screen("rooms"))
        self.menu_box.add_widget(room_button)
        room_label = Label(text=App.get_running_app().current_room, color=App.get_running_app().data_store.get("settings")["text_colour"])
        App.get_running_app().bind(current_room=lambda instance, value: setattr(room_label, 'text', value))
        self.menu_box.add_widget(room_label)
        history_button = Button(text="Load History", background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                                color=App.get_running_app().data_store.get("settings")["text_colour"])
        history_button.bind(on_press=self.load_history)
        self.menu_box.add_widget(history_button)

        self.add_widget(self.menu_box)

        #=== Add Scrollbar ===#
        self.orientation = "vertical"
        scroll_menu = ScrollableMessages()
        scroll_menu.size_hint_y = 0.9
        self.add_widget(scroll_menu)

        #=== Add Box to embed widgets ===#
        self.horizontal_box = BoxLayout(orientation="horizontal", size_hint_y="0.1")

        #=== Add Text Input box ===#
        self.messageInput = TextInput(multiline=False)
        self.horizontal_box.add_widget(self.messageInput)

        #=== Add Send Button ===#
        send_button = Button(text="Send", background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                             color=App.get_running_app().data_store.get("settings")["text_colour"])
        send_button.bind(on_press=self.send_message)
        self.horizontal_box.add_widget(send_button)

        self.add_widget(self.horizontal_box)

    #=== Message Sending Handler ===#
    def send_message(self, instance):
        #=== Takes the text from the message ===#
        message_text = self.messageInput.text.strip()
        user = App.get_running_app().username
        cur_room = App.get_running_app().current_room
        if message_text:

            #=== Encrypts and Sends the message ===#
            if message_text and App.get_running_app().server_public_key:
                encrypted_message = App.get_running_app().server_public_key.encrypt(
                    message_text.encode(),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

                sio.emit("send_message", {"username": user, "room": cur_room, "message": encrypted_message.hex()})

            self.messageInput.text = ""

    #=== Load Message History ===#
    def load_history(self, instance):
        current_room = App.get_running_app().current_room
        username = App.get_running_app().username
        sio.emit("get_history", {"room": current_room, "username": username})


#=== GUI Test - Messaging Screen ===#
class MessagingScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_widget(MessagingMenu())

#=== GUI Test - Room Menu ===#
class RoomMenuScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        #=== Create Room Menu ===#
        main_box = BoxLayout(orientation="vertical", padding=15, spacing=8)

        #=== Back Button and Server Name ===#
        top_bar = BoxLayout(orientation="horizontal", padding=10, spacing=5, size_hint_y=0.3)
        home_button = Button(text="Home Menu", size_hint_x=0.5, background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                             color=App.get_running_app().data_store.get("settings")["text_colour"])
        Server_Label = Label(text=App.get_running_app().name_of_server, size_hint_x=0.5, color=App.get_running_app().data_store.get("settings")["text_colour"])
        App.get_running_app().bind(name_of_server=lambda instance, value: setattr(Server_Label, 'text', value))
        home_button.bind(on_press=self.return_home)
        top_bar.add_widget(home_button)
        top_bar.add_widget(Server_Label)

        main_box.add_widget(top_bar)

        #=== Scrollable Server Room List ===#
        self.rooms_scroll = ScrollView(size_hint_y=0.7, scroll_y=1)
        self.rooms_scroll_box = BoxLayout(orientation="vertical", size_hint_y=None, height=800, spacing=10, padding=[10, 10])
        self.rooms_scroll.add_widget(self.rooms_scroll_box)
        available_rooms = App.get_running_app().list_of_rooms

        for room in available_rooms:
            room_button = Button(text=room, size_hint_y=None, height=20, padding=[10, 10],
                                 background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                                 color=App.get_running_app().data_store.get("settings")["text_colour"])
            room_button.bind(on_press=self.join_room)
            self.rooms_scroll_box.add_widget(room_button)

        main_box.add_widget(self.rooms_scroll)
        self.add_widget(main_box)

    def return_home(self, instance):
        sio.disconnect()
        App.get_running_app().change_screen("home")

    #=== Join Selected Room ===#
    def join_room(self, instance):
        username = App.get_running_app().username
        room = instance.text
        App.get_running_app().update_current_room(room)

        if username != "":
            #=== Clears Any previous room messages ===#
            messaging_screen = App.get_running_app().screenman.get_screen("messaging")
            scrollable_messages = messaging_screen.children[0].children[1]
            scrollable_messages.clear_messages()
            join_key = App.get_running_app().p_keys["public"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()

            sio.emit("join_room", {"username": username, "room": room, "client_public_key": join_key})
            App.get_running_app().change_screen("messaging")
        else:
            Error_Handler("Please enter a username at the settings menu.", "Identity Error")

    #=== Populates rooms after initialisation ===#
    def populate_rooms(self, rooms):
        self.rooms_scroll_box.clear_widgets()

        for room in rooms:
            room_button = Button(text=room, background_color=App.get_running_app().data_store.get("settings")["button_colour"], color=App.get_running_app().data_store.get("settings")["text_colour"])
            room_button.bind(on_press=self.join_room)
            self.rooms_scroll_box.add_widget(room_button)

class SettingsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        main_layout_1 = ScrollView(scroll_y=1)
        main_layout = BoxLayout(orientation="vertical", padding=20, spacing=10, size_hint_y=None, height=800)

        top_bar = BoxLayout(orientation="horizontal", padding=10, spacing=5, size_hint_y=0.2)
        home_button = Button(text="Home Menu", size_hint_x=0.5, background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                             color=App.get_running_app().data_store.get("settings")["text_colour"])
        settings_label = Label(text="Settings", size_hint_x=0.5,
                             color=App.get_running_app().data_store.get("settings")["text_colour"])
        home_button.bind(on_press=lambda x: App.get_running_app().change_screen("home"))
        top_bar.add_widget(home_button)
        top_bar.add_widget(settings_label)

        # === Server Data ===#
        server_box = BoxLayout(orientation="horizontal", padding=10, spacing=5)
        server_data = App.get_running_app().data_store.get("settings")["server_ip"]
        server_ip = "Server IP: " + server_data
        server_label = Label(text=server_ip, color=App.get_running_app().data_store.get("settings")["text_colour"])
        ipInput = TextInput(multiline=False)
        server_button = Button(text="Save", background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                             color=App.get_running_app().data_store.get("settings")["text_colour"])
        server_button.bind(on_press=lambda x: App.get_running_app().change_ip(ipInput.text.strip()))
        main_layout.add_widget(server_label)
        server_box.add_widget(ipInput)
        server_box.add_widget(server_button)
        main_layout.add_widget(server_box)

        #=== Name Data ===#
        name_box = BoxLayout(orientation="horizontal", padding=10, spacing=5)
        name_data = App.get_running_app().data_store.get("settings")["username"]
        username = "Username: " + name_data
        name_label = Label(text=username, color=App.get_running_app().data_store.get("settings")["text_colour"])
        nameInput = TextInput(multiline=False)
        name_button = Button(text="Save", background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                             color=App.get_running_app().data_store.get("settings")["text_colour"])
        name_button.bind(on_press=lambda x: App.get_running_app().change_name(nameInput.text.strip()))
        main_layout.add_widget(name_label)
        name_box.add_widget(nameInput)
        name_box.add_widget(name_button)
        main_layout.add_widget(name_box)

        #=== Background Data ===#
        background_box = BoxLayout(orientation="horizontal", padding=10, spacing=5)
        background_data = App.get_running_app().data_store.get("settings")["background_colour"]
        bg = "Background (Hex): " + background_data
        background_label = Label(text=bg, color=App.get_running_app().data_store.get("settings")["text_colour"])
        bgInput = TextInput(multiline=False)
        bg_button = Button(text="Save", background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                           color=App.get_running_app().data_store.get("settings")["text_colour"])
        bg_button.bind(on_press=lambda x: App.get_running_app().change_bg(bgInput.text.strip()))
        main_layout.add_widget(background_label)
        background_box.add_widget(bgInput)
        background_box.add_widget(bg_button)
        main_layout.add_widget(background_box)

        # === Text Data ===#
        text_box = BoxLayout(orientation="horizontal", padding=10, spacing=5)
        text = App.get_running_app().data_store.get("settings")["text_colour"]
        text_ = "Text (Hex): " + text
        text_label = Label(text=text_, color=App.get_running_app().data_store.get("settings")["text_colour"])
        textInput = TextInput(multiline=False)
        text_button = Button(text="Save", background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                           color=App.get_running_app().data_store.get("settings")["text_colour"])
        text_button.bind(on_press=lambda x: App.get_running_app().change_text(textInput.text.strip()))
        main_layout.add_widget(text_label)
        text_box.add_widget(textInput)
        text_box.add_widget(text_button)
        main_layout.add_widget(text_box)

        # === Button Data ===#
        BT_box = BoxLayout(orientation="horizontal", padding=10, spacing=5)
        bt = App.get_running_app().data_store.get("settings")["text_colour"]
        bt_ = "Button (Hex): " + bt
        bt_label = Label(text=bt_, color=App.get_running_app().data_store.get("settings")["text_colour"])
        btInput = TextInput(multiline=False)
        bt_button = Button(text="Save",
                             background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                             color=App.get_running_app().data_store.get("settings")["text_colour"])
        bt_button.bind(on_press=lambda x: App.get_running_app().change_bt(btInput.text.strip()))
        main_layout.add_widget(bt_label)
        BT_box.add_widget(btInput)
        BT_box.add_widget(bt_button)
        main_layout.add_widget(BT_box)

        main_layout_1.add_widget(main_layout)
        big_box = BoxLayout(orientation="vertical")
        big_box.add_widget(top_bar)
        big_box.add_widget(main_layout_1)
        self.add_widget(big_box)

#=== GUI Test - Main Menu ===#
class MainMenuScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        #=== Box Layout for Main Menu ===#
        main_layout = BoxLayout(orientation="vertical", padding=20, spacing=10)

        #=== Button to access Message Menu ===#
        MessageMenuButton = Button(text="Go to Messaging", size_hint=(1, 0.3),
                                   background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                                   color=App.get_running_app().data_store.get("settings")["text_colour"])
        MessageMenuButton.bind(on_press=self.connection_function)
        main_layout.add_widget(MessageMenuButton)

        # === Button to access Settings Panel ===#
        settings_button = Button(text="Open Settings", size_hint=(1, 0.3),
                                 background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                                 color=App.get_running_app().data_store.get("settings")["text_colour"])
        settings_button.bind(on_press=lambda x: App.get_running_app().change_screen("settings"))
        main_layout.add_widget(settings_button)

        self.add_widget(main_layout)

    def connection_function(self, instance):

        server_ip = App.get_running_app().data_store.get("settings")["server_ip"]
        username = App.get_running_app().data_store.get("settings")["username"]

        # === Connect to the Server ===#
        if not sio.connected:
            try:
                get_public_key()
                sio.connect("http://" + str(server_ip))
                UrlRequest(("http://" + str(server_ip) + "/get_rooms"), self.find_rooms)
                UrlRequest(("http://" + str(server_ip) + "/get_name"), self.find_name)
                App.get_running_app().change_screen("rooms")
            except Exception as e:
                Error_Handler("Server IP Error, please change IP in settings or Server is offline", e)
                App.get_running_app().change_screen("home")
        else:
            App.get_running_app().change_screen("rooms")

    #=== Get available rooms from server ===#
    def find_rooms(self, request, result):
        App.get_running_app().update_rooms(result["rooms"])

    #=== Get Server Name ===#
    def find_name(self, request, result):
        App.get_running_app().update_server_name(result)


#=== Error handling popup ===#
def Error_Handler(error_message, exception):
    #=== Layout of the popup ===#
    error_content = BoxLayout(orientation="vertical")
    error_content.add_widget(Label(text=error_message, color=App.get_running_app().data_store.get("settings")["text_colour"]))
    error_scroll = ScrollView(size_hint=(1,1))
    error_scroll.add_widget(Label(text=fill(str(exception), width=50), size_hint_y=None))
    close_error = Button(text="Close", size_hint=(1, 0.3),
                         background_color=App.get_running_app().data_store.get("settings")["button_colour"],
                         color=App.get_running_app().data_store.get("settings")["text_colour"])
    error_content.add_widget(error_scroll)
    error_content.add_widget(close_error)

    #=== Popup Instance ===#
    popup = Popup(title="Connection Error", content=error_content, size_hint=(0.7, 0.4))
    close_error.bind(on_press=popup.dismiss)
    popup.open()

#=== Get Server Public Key for Encryption ===#
def get_public_key():
    def on_success(req, result):
        App.get_running_app().server_public_key = serialization.load_pem_public_key(result["public_key"].encode())

    def on_failure(req, result):
        Error_Handler("Server Public Key Error:", result)
        App.get_running_app().change_screen("home")

    ip_address = App.get_running_app().server_ip_address
    request = f"http://{ip_address}/get_public_key"
    UrlRequest(request, on_success=on_success, on_failure=on_failure)

#=== Creates Private/Public Keys for RSA Encryption ===#
def create_RSA_keys():
    # === Generate Asymmetric Key ===#
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    #=== Due to Android issues, do not save to file, only to memory ===#
    return {"private": private_key, "public": public_key}

#=== Decrypts incoming messages from server ===#
def decrypt_message(data):

    decrypted_message = App.get_running_app().p_keys["private"].decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

#=== Main App ===#
class MainApp(App):

    #=== Safely Stored Global Variables ===#
    title = "Rameen's NEA"
    list_of_rooms = []
    server_ip_address = StringProperty("")
    username = StringProperty("")
    server_public_key = None
    background_colour = StringProperty("000000")
    text_colour = StringProperty("FFFFFF")
    button_colour = StringProperty("808080")
    #=== Load Local Keys ===#
    p_keys = create_RSA_keys()
    current_room = StringProperty("")
    name_of_server = StringProperty("")
    #=== Create JSONSTORE ===#
    data_store = JsonStore("savedata.json")
    if not data_store.exists("settings"):
        data_store.put("settings", server_ip="127.8.8.1", username="user", background_colour="000000", text_colour="FFFFFF", button_colour="808080")
    username = data_store.get("settings")["username"]
    server_ip_address = data_store.get("settings")["server_ip"]
    background_colour = data_store.get("settings")["background_colour"]
    text_colour = data_store.get("settings")["text_colour"]
    button_colour = data_store.get("settings")["button_colour"]


    #=== App Build Function ===#
    def build(self):

        bg_colour = get_color_from_hex(App.get_running_app().data_store.get("settings")["background_colour"])

        Window.clearcolor = bg_colour

        #=== Load Screen Manager ===#
        self.screenman = ScreenManager()
        self.screenman.add_widget(MainMenuScreen(name="home"))
        self.screenman.add_widget(MessagingScreen(name="messaging"))
        self.screenman.add_widget(RoomMenuScreen(name="rooms"))
        self.screenman.add_widget((SettingsScreen(name="settings")))

        return self.screenman

    #=== Change Current Screen ==#
    def change_screen(self, screen_name):
        self.screenman.current = screen_name

    #=== Update available rooms list ===#
    def update_rooms(self, data):
        self.list_of_rooms = data

        #=== Dynamically change the rooms when connected ===#
        room_screen = self.screenman.get_screen("rooms")

        if room_screen:
            room_screen.populate_rooms(self.list_of_rooms)

    #=== Update Server Name ===#
    def update_server_name(self, data):
        self.name_of_server = data

    #=== Update Server Address ===#
    def update_address(self, data):
        self.server_ip_address = data

    #=== Update UserName ===#
    def update_username(self, data):
        self.username = data

    # === Update UserName ===#
    def update_current_room(self, data):
        self.current_room = data

    def change_ip(self, newdata):
        # === Keep Old Values ===#
        name = App.get_running_app().data_store.get("settings")["username"]
        background = App.get_running_app().data_store.get("settings")["background_colour"]
        text = App.get_running_app().data_store.get("settings")["text_colour"]
        button = App.get_running_app().data_store.get("settings")["button_colour"]
        App.get_running_app().data_store.put("settings", server_ip=newdata, username=name, background_colour=background, text_colour=text, button_colour=button)
        App.get_running_app().server_ip_address = newdata

    def change_bt(self, newdata):
        #=== Keep Old Values ===#
        name = App.get_running_app().data_store.get("settings")["username"]
        ip = App.get_running_app().data_store.get("settings")["server_ip"]
        text = App.get_running_app().data_store.get("settings")["text_colour"]
        background = App.get_running_app().data_store.get("settings")["background_colour"]
        App.get_running_app().data_store.put("settings", server_ip=ip, username=name, background_colour=background,
                                             text_colour=text, button_colour=newdata)
        App.get_running_app().button_colour = newdata

    def change_name(self, newdata):
        # === Keep Old Values ===#
        ip = App.get_running_app().data_store.get("settings")["server_ip"]
        background = App.get_running_app().data_store.get("settings")["background_colour"]
        text = App.get_running_app().data_store.get("settings")["text_colour"]
        button = App.get_running_app().data_store.get("settings")["button_colour"]
        App.get_running_app().data_store.put("settings", server_ip=ip, username=newdata, background_colour=background, text_colour=text, button_colour=button)
        App.get_running_app().username = newdata

    def change_bg(self, newdata):
        # === Keep Old Values ===#
        name = App.get_running_app().data_store.get("settings")["username"]
        ip = App.get_running_app().data_store.get("settings")["server_ip"]
        text = App.get_running_app().data_store.get("settings")["text_colour"]
        button = App.get_running_app().data_store.get("settings")["button_colour"]
        App.get_running_app().data_store.put("settings", server_ip=ip, username=name, background_colour=newdata, text_colour=text, button_colour=button)
        App.get_running_app().background_colour = newdata

    def change_text(self, newdata):
        # === Keep Old Values ===#
        name = App.get_running_app().data_store.get("settings")["username"]
        ip = App.get_running_app().data_store.get("settings")["server_ip"]
        button = App.get_running_app().data_store.get("settings")["button_colour"]
        background = App.get_running_app().data_store.get("settings")["background_colour"]
        App.get_running_app().data_store.put("settings", server_ip=ip, username=name, background_colour=background,
                                             text_colour=newdata, button_colour=button)
        App.get_running_app().text_colour = newdata


#=== Main function ===#
if __name__ == '__main__':
    MainApp().run()
