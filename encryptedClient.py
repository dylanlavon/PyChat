# Dylan Britain
# Chat Project - Part 2
# CS 4326 - Shengli Yuan
# 10/02/2022

###############################################################################################

# Import socket and AES to support encrypted messaging between a client and a server on a network
import socket
from Crypto.Cipher import AES

# Import os for cls command
import os

# Declare the symmetric private key
KEY = b'H\x86\xd5\xa0)\xecf\\|4\xf3\xc8xJ\xef\xa0'

# Initialize the client and connect them to the server with an arbitrary port declared by the server.py script
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("10.0.0.76", 9999))

###############################################################################################

def encrypt(msg):
    """
    Define the encrypting function, making use of PyCryptodome's AES library.
    Takes a plain text message as its parameter.
    """
    
    # Create a new AES cipher object. Cipher objects contain a nonce, tag, and the ciphertext.
    cipher = AES.new(KEY, AES.MODE_EAX)

    # The nonce is a single-use number used to prevent replay attacks.
    nonce = cipher.nonce

    # Encrypt ciphertext and tag to prepare for transport.
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))

    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    """
    Define the decrypting function, making use of PyCryptodome's AES library.
    Takes the sent message's nonce, ciphertext, and tag as its parameters.
    """

    # Assign the cipher and decrypt the transmitted message.
    cipher = AES.new(KEY, AES.MODE_EAX, nonce = nonce)
    plainText = cipher.decrypt(ciphertext)

    # Return the deciphered plaintext if the tag is verified.
    try:
        cipher.verify(tag)
        return plainText.decode('ascii')

    # Return an error message if the tag is corrupted.
    except:
        return "Tag could not be verified!"

###############################################################################################

def sendInputMessage(userInput):
    """
    Define the sendInputMessage function. Individually sends nonce, cipherText, and tag to the other user.
    The message to be encrypted is altered depending on whether the user is currently logged in or not.
    Takes the user's input as a plain text parameter.
    """

    # Do not alter the userInput if the client has not successfully logged in yet.
    if not loggedIn:
        msgToEncrypt = userInput

    # If the client has successfully logged in, begin each message with their username>
    else:
        msgToEncrypt= f"{username}> {userInput}"

    # Pull the nonce, cipherText, and tag from the encrypted userInput.
    nonce, cipherText, tag = encrypt(msgToEncrypt)

    # Send the nonce and await confirmation.
    client.send(nonce)
    waitForConf = client.recv(1024)

    # Send the cipherText and await confirmation.
    client.send(cipherText)
    waitForConf = client.recv(1024)

    # Send the tag and await confirmation.
    client.send(tag)
    waitForConf = client.recv(1024)

def receiveMsg():
    """
    Define the receiveMsg function. Individually receives nonce, cipherText, and tag.
    Confirmation packets are sent in ascii after receiving each piece of data.
    plainText is then decrypted and returned.
    """

    # Receive the nonce and send confirmation.
    nonce = client.recv(1024)
    client.send("Msg received".encode('ascii'))

    # Receive the cipherText and send confirmation.
    cipherText = client.recv(1024)
    client.send("Msg received".encode('ascii'))

    # Receive the tag and send confirmation.
    tag = client.recv(1024)
    client.send("Msg received".encode('ascii'))

    # Decrypt and return the plainText
    plainText = decrypt(nonce, cipherText, tag)
    return plainText

###############################################################################################

#Initialize variables for loops
done = False
loggedIn = False

###############################################################################################

# Initial prompt for login credentials
os.system('cls')
print(r"""                                             
,------.           ,-----.,--.               ,--.   
|  .--. ',--. ,--.'  .--./|  ,---.  ,--,--.,-'  '-. 
|  '--' | \  '  / |  |    |  .-.  |' ,-.  |'-.  .-' 
|  | --'   \   '  '  '--'\|  | |  |\ '-'  |  |  |   
`--'     .-'  /    `-----'`--' `--' `--`--'  `--' _client
         `---'                                           // Dylan Britain // Shengli Yuan CS4326 // 10/02/2022 //
""")
print("\n☆ Welcome to PyChat. This script works securely in tandem with a seperate server script by using TCP Sockets and AES encryption.")
print("☆ For the purposes of this project, the symmetric private key is hard coded in both the client-side and server-side scripts.")
print("☆ These scripts make use of the built-in sockets library, as well as the popular cryptography library 'PyCryptodome.' → https://pypi.org/project/pycryptodome/")
print("☆ After logging in, you may close the connection by entering 'done'.")
print("☆ User credentials are stored server-side in 'passwords.txt' in the format 'username::password'.")
print("☆ To begin, please enter your username and password in the format 'username::password'\n")

###############################################################################################

# Start the logging in process
while not loggedIn:

    # Send the following credentials to the server for verification
    userInput = input("username::password -> ")
    sendInputMessage(userInput)

    # Wait for reply from server
    incomingMsg = receiveMsg()
    print(incomingMsg)

    # If the server returns 'Login successful!', log the user in and end the loop.
    if incomingMsg == "Login successful.\n":
        loggedIn = True

        # Declare the username to be displayed when chatting
        username = userInput.split(":")[0]
        
###############################################################################################

# Start the main chat loop
while not done:
    
    # Send out a new message.
    sendInputMessage(input(f"{username}: "))

    # Assign the incomingMsg.
    try:
        incomingMsg = receiveMsg()

    # Break the loop if the server closes the connection.
    except:
        print("Connection closed. Thank you for using PyChat!")
        break
    
    # Close the connection of the user enters 'done'.
    if incomingMsg == 'Server> done':
        print("\nThe server has terminated the connection. Thanks for using PyChat!")
        break

    # Print the incomingMsg
    print(incomingMsg)


    
###############################################################################################
