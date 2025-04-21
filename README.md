# NEA-Messaging-App
A messaging application that I created for my Non-Exam-Assessment in Computer Science, featuring a client and a server program, allowing users to host their own server. The client is a Windows executable and the server consists of python scripts.


The client .exe file has been tested to work on Windows 11.

The Server has 2 python scripts, a key maker and the main script, the key maker should be ran once intially, then afterwards only the main script should be used, this is for the encryption of messages stored within an SQLite database.

The server also has some HTML and CSS files that are used for a webUI config page, to change the rooms and the name of the server.

![image](https://github.com/user-attachments/assets/c34bde75-1dc9-4d69-8efa-d1ce5780f2d8)
This is an example image, as the client app can customise the colours of the background, text and buttons with hexadecimal colour codes in the settings, but the app must be closed and reopened for visual changes to occur.

RSA encryption between client and server exists, and messages are encrypted before being stored in a database, however there is a security flaw in the config page, where someone can bypass the login, so if anyone wants to use this app, make sure to avoid publicly port forwarding it.
