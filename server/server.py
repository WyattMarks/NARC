## Super simple relay chat protocol.
#  This is the server implmentation. 
#  NARC - Not Another Relay Chat 
#  https://github.com/wyattmarks/narc
#  TODO: Refactor the code more, each file is getting spaget

import socket
import threading
import json

from argon2 import PasswordHasher
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

from sv_client import Client

host = ""
port = 0xBEEF #48879





		

			

## The actual server object
class Server:
	## Must be given an IP and port to listen on
	def __init__(self, host, port):
		self.host = host
		self.port = port
		
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create socket object

		self.clients = [] #Empty list for clients
		self.passwords = {} #Empty dictionary for nick / password combos
		self.channels = {}

		randomGenerator = Random.new().read
		self.rsaKey = RSA.generate(1024, randomGenerator)
		self.decryptor = PKCS1_OAEP.new(self.rsaKey)
		self.hasher = PasswordHasher()

		self.load_passwords()
		self.load_channels()

	def load_passwords(self):
		try:
			f = open("auth.json", "r")
			self.passwords = json.load(f)
			f.close()
		except Exception as e:
			self.save_passwords()

	def save_passwords(self):
		try:
			f = open("auth.json", "w")
			f.write(json.dumps(self.passwords))
			f.close()
		except Exception as e:
			print(f"Error writing auth.json.. {e}")

	def load_channels(self):
		try:
			f = open("channels.json", "r")
			self.channels = json.load(f)
			f.close()
		except Exception as e:
			self.save_channels()

	def save_channels(self):
		try:
			f = open("channels.json", "w")
			f.write(json.dumps(self.channels))
			f.close()
		except Exception as e:
			print(f"Error writing channels.json.. {e}")
		
	## Function to create client object and begin the infinite loop call
	def handle_client(self, client_socket, address):
		client = Client(client_socket, address, self)
		self.clients.append(client)
		client.begin()

	## Open the socket and start listening. Allow REUSEADDR so that we can debug faster
	def start(self):
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((host, port)) #Bind to the given host and port
		self.socket.listen() # Start listening
		
		print("NARC Server Starting...")
		while True: # Main infinite loop. Spawns threads to handle each client, and that is it
			client, address = self.socket.accept() # Wait for a connection
			cli_thread = threading.Thread(target=self.handle_client, args=(client, address)) #Create a thread object to call handle_client
			cli_thread.setDaemon(True) #Set to daemon so that the process doesn't wait for clients to disconnect if we stop
			cli_thread.start() #Call this client's thread

	## Stop the server
	def stop(self):
		self.socket.close() #Close the socket when we stop

	def broadcast(self, channel, message, exclude=[]):
		for c in self.clients:
			if c not in exclude and c.channel == channel:
				c.send((message + "\r\n").encode())
				
	## Broadcast the arrival of someone
	def arrival(self, client, channel):
		if channel is None:
			client.send("Welcome to NARC Server 0.0.2!")
			client.send(f"You are now known as {client.nick}.")

		if channel is not None and channel in self.channels: #If there is a MOTD currently set, send it
			owner, motd, _e = self.channels[channel]
			client.send(f"{motd}")

		for c in self.clients:
			if (c.channel != None and c.channel == channel): # Tell everyone that someone new connected
				c.send(f"Welcome {client.nick} to {channel}!")

	## Broadcast the departure
	def departure(self, client):
		for c in self.clients:
			if (c.channel != None and c.channel == client.channel and c != client): # Tell everyone that someone left
				c.send(f"{client.nick} has left {client.channel}..")
	
	
	def is_channel_claimed(self, channel):
		for c in self.channels:
			if channel == c:
				return True

		return False

	def get_channel_owner(self, channel):
		owner, motd, _e = self.channels[channel]
		return owner

	def claim_channel(self, nick, channel):
		self.channels[channel] = (nick, f"Welcome to {channel}", False)
		self.save_channels()

	def encrypt_channel(self, channel, encrypted):
		if encrypted:
			for client in self.clients:
				if client.channel == channel:
					if client.authed:
						client.send("Encryption was enabled for this channel.")
						client.request_pubkey()
					else:
						client.send("Sorry, this channel has been encrypted and now requires you to be registered.")
						client.channel = None
			owner, motd, _e = self.channels[channel]
			self.channels[channel] = (owner, motd, True)
		else:
			self.broadcast(channel, "Encryption was disabled for this channel.")
			owner, motd, _e = self.channels[channel]
			self.channels[channel] = (owner, motd, False)
		self.save_channels()

	def is_channel_encrypted(self, channel):
		if channel not in self.channels:
			return False
		
		owner, motd, encrypted = self.channels[channel]
		return encrypted


	## Set a channel's MOTD
	def set_motd(self, client, motd):
		owner, _m, _e = self.channels[client.channel] 
		self.channels[client.channel] = (client.nick, motd, _e)
		self.save_channels()

	def get_motd(self, channel):
		owner, motd, _e = self.channels[channel]
		return motd

	## Remove a client
	def disconnect(self, client):
		self.departure(client)
		self.clients.remove(client)

	## Determine the availability of a nickname
	def nick_available(self, nick):
		if nick == "Anonymous":
			return False
		for c in self.clients:
			if c.nick == nick:
				return False

		return True

	## Return all clients inside a channel
	def get_online(self, channel):
		clients = []
		for c in self.clients:
			if c.channel == channel:
				clients.append(c)

		return clients

	def is_nick_registered(self, nick):
		return nick in self.passwords

	def get_salt(self, nick):
		(password, salt) = self.passwords[nick]
		return salt

	def register(self, client, password, salt):
		print(f"{client.nick} has now been registered")
		
		self.passwords[client.nick] = (password, salt)
		self.save_passwords()
		client.send(f"Congratulations, {client.nick} is now registered to you.")

	def auth(self, nick, password):
		(hash, salt) = self.passwords[nick]
		try:
			self.hasher.verify(hash, password)
			return True
		except:
			return False







if __name__ == "__main__":
	server = Server(host, port)
	try:
		server.start()
	except:
		server.stop()