## Super simple relay chat protocol.
#  This is the client implmentation. 
#  You could get away with a simple telnet connection - but then you have to specify /chat for sending messages
#  NARC - Not Another Relay Chat 
#  https://github.com/wyattmarks/narc

import socket
import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from base64 import b64encode, b64decode

## Client object for the client side
#  Simply sends the commands you give it to the server
#  Handles printing and getting input to make it more cohesive than just a telnet session
class Client:
	def __init__(self, ip, port):
		self.nick = "Anonymous"
		self.old_nick = self.nick
		self.ip = ip
		self.port = port

		self.waiting_for_password = False

		randomGenerator = Random.new().read
		self.rsaKey = RSA.generate(1024, randomGenerator)
		self.decryptor = PKCS1_OAEP.new(self.rsaKey)
		self.channel = None
		self.channel_encrypted = False

		self.aes_key = None
		

	def connect(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.connect((self.ip, self.port))


	def print_responses(self):
		import sys
		while True:
			try:
				response = self.socket.recv(4200)

				if response == b'':
					raise socket.error

				if response[0:10].decode() == "CHANNELKEY":
					self.aes_key = self.decryptor.decrypt(response[10:])
					self.channel_encrypted = True
					continue

				if response[0:10].decode() == "ENCRYPTED:":
					if self.aes_key is not None: #shouldnt happen, but eh
						response = self.decrypt(response[10:]).decode()
					else:
						print("Error, we got an ecrypted message but don't have a aes key to use")
						self.socket.send(self.rsaKey.publickey().exportKey())
						continue

				response = response.decode() if type(response) == bytes else response

				if response.startswith(f"{self.nick} is now known as ") or response.startswith("Welcome back, "):
					self.nick = response.strip().replace(f"{self.nick} is now known as ", "").replace("Welcome back, ", "")
					self.nick = self.nick[0:len(self.nick)-1]

				if not response.strip().startswith(f"<{self.nick}> "):
					if response.startswith("-----BEGIN PUBLIC KEY-----"):
						self.encryptor = PKCS1_OAEP.new(RSA.importKey(response))
						self.waiting_for_password = True
						sys.stdout.write('\033[2K\033[1G')
						print("Password: ", end="")
						sys.stdout.flush()
					elif response.startswith("PUBKEYREQ"):
						self.socket.send(self.rsaKey.publickey().exportKey())
					else:
						sys.stdout.write('\033[2K\033[1G') #Get rid of the <user> in console from the input() call
						print(response.strip())
						print(f"<{self.nick}> ", end="") #put the <user> back so it looks right
						sys.stdout.flush() #flush stdout so that <user> actually appears
			except socket.error:
				sys.stdout.write('\033[2K\033[1G') #Get rid of the <user> in console from the input() call
				print("Connection lost, attempting to reconnect..")
				connected = False
				while not connected:
					try: 
						self.connect()
						connected = True
					except socket.error:
						print("Failed again, retrying in 5 seconds..")
						from time import sleep
						sleep(5)
				print("Connected!")
				self.__init__(self.ip, self.port) #reset everything
				print(f"<{self.nick}> ", end="") 
				sys.stdout.flush()

	def send(self, message):
		if self.channel_encrypted:
			self.socket.send("ENCRYPTED:".encode() + self.encrypt(message))
		else:
			self.socket.send(message)

	def encrypt(self, message):
		iv = Random.new().read(16)
		cipher = AES.new(self.aes_key, mode=AES.MODE_CFB,IV=iv)
		encrypted_message = cipher.encrypt(message)   
		return b64encode(iv + encrypted_message)

	def decrypt(self, message):
		message = b64decode(message)
		iv = message[0:16]
		message = message[16:]
		cipher = AES.new(self.aes_key, AES.MODE_CFB, IV=iv)
		return cipher.decrypt(message)

	def handle_input(self):
		while True:
			try:
				message = input(f"<{self.nick}> ")
				if len(message) > 0:
					if self.waiting_for_password:
						password = self.encryptor.encrypt(message.encode())
						self.socket.send(password)
						self.waiting_for_password = False
					elif message.startswith("/"): #If it starts with / then it is a command, and we should not prepend /chat
						if message.startswith("/join #"):
							self.channel = message.replace("/join ", "")
							self.channel_encrypted = False

						self.send(f"{message} \r\n".encode())

						if message.startswith("/quit") or message.startswith("/exit"):
							raise KeyboardInterrupt #hacky way of making it exit, lol
					else:
						self.send(f"/chat {message}\r\n".encode()) #if we don't specify a command, assume that it should be a chat message
			except KeyboardInterrupt:
				print("\nDisconnecting...")
				break
		


if __name__ == "__main__":
	import sys

	server = "127.0.0.1"
	if len(sys.argv) != 2:
		print('You must give a server address as the only argument')
		exit(0) #comment out for local testing
	else:
		server = sys.argv[1]


	c = Client(server, 0xBEEF)

	try:
		c.connect()
	except ConnectionRefusedError:
		print(f"Server not running on {server}")
		exit(0)

	print_thread = threading.Thread(target=c.print_responses) #Put this in a thread so the socket.recv call doesn't block us from sending input
	print_thread.setDaemon(True) #Make it a deamon so that the program doesn't hang around waiting for the thread
	print_thread.start()
	c.handle_input()