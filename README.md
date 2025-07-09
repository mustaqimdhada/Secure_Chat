# 🔐 Secure Chat App

📌 **Overview**This project is a GUI-based Secure Chat Application built using Python and CustomTkinter. It enables users to communicate securely over a network using RSA encryption. The app features a modern user interface, an emoji picker for enhanced messaging, and robust encryption to ensure the privacy of conversations.

✨ **Features**

- 🔒 Secure communication using RSA encryption  
- 🖥️ Modern and minimal GUI using CustomTkinter  
- 😀 Emoji picker for enhanced messaging  
- 🌐 Server and client modes for flexible communication  
- 🔑 Passcode exchange for secure connection setup

⚙️ **Installation**

📋 **Prerequisites**

- 🐍 Python 3.x  
- 📦 Required Python libraries:
  customtkinter, pycryptodome

🚀 **Steps**

1. Clone the repository:  

   ```
   git clone https://github.com/mustaqimdhada/secure_chat.git
   cd secure_chat
   
   ```
2. Install dependencies:  

   ```
   pip install customtkinter pycryptodome
   
   ```
3. Run the application:
   ```
   - For server mode: python secure_chat.py server
   - For client mode: python secure_chat.py client
   ```

🛠️ **Usage**

🔍 **Establishing a Connection**

- In server mode, the application will wait for a client to connect.  
- In client mode, the application will attempt to connect to the server.

🔑 **Passcode Exchange**

- A passcode will be generated and displayed. Share this passcode with your partner to establish a secure connection.  
- The partner must enter the passcode to proceed.

💬 **Chatting**

- Type your message in the input field and press Enter or click the "Send" button to send the message.  
- Use the emoji button to open the emoji picker and insert emojis into your messages.

📸 **Screenshots**

-<img src="https://github.com/user-attachments/assets/4390da10-2ae7-4100-a333-2b1059ef78fe" alt="Chat Interface" width="600"/>
-<img src="https://github.com/user-attachments/assets/74cef31e-4b10-47dd-a6af-853d09c88e58" alt="Emoji Picker" width="600"/>
-<img src="https://github.com/user-attachments/assets/01828a5d-4dc2-45a3-b845-a9097a12c051" alt="Random Password Generation" width="600"/>


🎥 **Demo Video**
