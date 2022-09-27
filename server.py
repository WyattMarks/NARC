## Super simple relay chat protocol.
#  This is the server implmentation. 
#  NARC - Not Another Relay Chat 
#  https://github.com/wyattmarks/narc


import socket
import threading
import json

from argon2 import PasswordHasher
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

host = ""
port = 0xBEEF #48879



## Client object for serverside code
class Client:
	## Must be given the client socket, its IP address, and the server object
	def __init__(self, client_socket, address, server):
		print(f'New client from {address}')
		self.socket = client_socket
		self.ip, self.port = address
		self.server = server

		self.nick = "Anonymous"
		self.authed = False
		self.channel = None

		self.commands = { ## Command dictionary makes parsing input much easier
			"/join": self.join_channel,
			"/channels": self.list_channels,
			"/chat": self.send_chat,
			"/nick": self.set_nick,
			"/auth": self.auth,
			"/login": self.auth,
			"/register": self.register,
			"/motd": self.set_motd,
			"/ping": self.pong,
			"/quit": self.quit,
			"/exit": self.quit,
			"/online": self.online,
			"/help": self.help,
			"/claim": self.claim,
			"/encrypt": self.encrypt_channel,
		}

		self.encryptor = None

	## Start the connection. Blocks until connection ends
	def begin(self):
		self.connected = True

		# Let the client know the connection was successful
		self.server.arrival(self, None)

		while self.connected:
			try:
				msg = self.socket.recv(4096)
				if msg[0:10].decode() == "ENCRYPTED:":
					msg = self.server.decryptor.decrypt(msg[10:])
				msg = msg.decode()
				
				print(f"{self.nick} ({self.ip})> {msg.strip()}")

				if msg.startswith("-----BEGIN PUBLIC KEY-----"):
					self.encryptor = PKCS1_OAEP.new(RSA.importKey(msg))
				else:
					valid = False
					for command in self.commands:
						if msg.startswith(command + " "):
							self.commands[command](msg.strip().replace(command + " ", "")) #Call the callback for this command from the dictionary
							valid = True
							break
					
					if not valid:
						self.send("Error, command not found.\r\n".encode())

			except BrokenPipeError: #Broken pipe means that client disconnected, let people know
				print(f"{self.nick} has disconnected..")
				self.server.disconnect(self) #handle disconnection
				self.connected = False #let the infinite loop stop
				break
			except Exception as e:
				print(f"Exception on client {self.nick}({self.ip}): {e}")
			
		self.socket.close() #close the socket after the infinite loop ends

	def send(self, bytes):
		if self.channel is not None and self.server.is_channel_encrypted(self.channel):
			if self.encryptor is None:
				self.request_pubkey() #shouldnt happen, but eh? ask again I guess
			else:
				self.socket.send("ENCRYPTED:".encode() + self.encryptor.encrypt(bytes))
		else:
			self.socket.send(bytes)

	def request_pubkey(self):
		self.send("PUBKEYREQ\r\n".encode())

	## Join the given channel
	def join_channel(self, msg):
		if msg.startswith("#"): # Just like IRC, channels start with #
			if self.server.is_channel_encrypted(msg):
				if self.authed:
					if self.encryptor is None:
						self.request_pubkey()
				else:
					self.send("You must be registered to join this channel because it is encrypted.\r\n".encode())
					return

			self.send(f"Joining {msg}...\r\n".encode())
			self.server.arrival(self, msg) # Tell anyone in the channel someone joined
			self.server.departure(self) # Tell anyone in the old channel that someone left
			self.channel = msg
		else:
			self.send(f"Channel names must begin with a #\r\n".encode())
		
	## Broadcast a message to the channel the client is in
	def send_chat(self, msg):
		if self.channel != None:
			self.server.chat(self, msg) # Broadcast the chat message in this channel
		else:
			self.send("You must join a channel first (/join)\r\n".encode())

	## Set the client's nick name
	def set_nick(self, msg):
		if msg != "/nick":
			if self.server.is_nick_registered(msg):
				self.send(f"Sorry, {msg} is registered. If this is your nick, use /auth <nick> to login\r\n".encode())
				return

			if self.server.nick_available(msg):
				self.authed = False
				self.server.broadcast(self.channel, f"{self.nick} is now known as {msg}!")
				self.nick = msg
			else:
				self.send(f"Sorry, {msg} is already in use.\r\n".encode())
		else:
			self.send("You must give a nickname to use after /nick\r\n".encode())

	## The the current channel's nick name
	def set_motd(self, msg):
		if msg == "/motd":
			self.send((self.server.get_motd(self.channel) + "\r\n").encode())
			return
		
		if self.channel is None:
			self.send("You must be a channel to see a channel's MOTD..\r\n".encode())
			return

		if not self.server.is_channel_claimed(self.channel):
			self.send("This channel is not claimed, and therefore has no MOTD. Claim it with /claim!\r\n".encode())
			return

		if not self.authed:
			self.send((self.server.get_motd(self.channel) + "\r\n").encode())
			return

		if self.nick != self.server.get_channel_owner(self.channel):
			self.send((self.server.get_motd(self.channel) + "\r\n").encode())
			return
		
		self.server.set_motd(self, msg)
		self.send("Channel MOTD set.\r\n".encode())

			

	## Ping
	def pong(self, msg):
		self.send("Pong!\r\n".encode())

	## End the connection
	def quit(self, msg):
		self.send("Goodbye!\r\n".encode())
		self.server.departure(self)
		self.connected = False

	## List the currently connection clients in this channel
	def online(self, msg):
		if self.channel != None:
			clients = self.server.get_online(self.channel)
			message = f"There are currently {len(clients)} people online in {self.channel}\r\n"
			for c in clients:
				message += f"\t{c.nick}\r\n"
			self.send(message.encode())

		else:
			self.send("Join a channel to see who's online in that channel\r\n".encode())

	def list_channels(self, msg):
		message = f"There are currently {len(self.server.channels)} registered channels\r\n"
		for c in self.server.channels:
			message += f"\t{c}\r\n"
		self.send(message.encode())


	## List the command dictionary
	def help(self, msg):
		message = "Available Commands:\r\n"
		for cmd in self.commands:
			message += f"\t{cmd}\r\n"

		self.send(message.encode())

	## Login with password
	def auth(self, msg):
		if msg == "/auth":
			self.send("You must provide a nickname to login to\r\n".encode())
			return

		if not self.server.is_nick_registered(msg):
			self.send("This nickname is not registered\r\n".encode())
			return

		if self.authed:
			self.send("You are already logged in..\r\n".encode())
			return


		self.send(self.server.rsaKey.publickey().exportKey())
		if self.server.auth(msg, self.server.decryptor.decrypt(self.socket.recv(4096).strip()) + self.server.get_salt(msg).encode()):
			self.nick = msg
			self.send(f"Welcome back, {self.nick}!\r\n".encode())
			self.server.broadcast(self.channel, f"{self.nick} has logged in\r\n", exclude=[self])
			self.authed = True
		else:
			self.send("Sorry, that is not the correct password.\r\n".encode())
			

	## Register a nick with a password
	def register(self, msg):
		if self.server.is_nick_registered(self.nick):
			self.send("This nickname is already registered\r\n".encode())
			return

		if self.nick == "Anonymous":
			self.send("You must first select a nick name (/nick)\r\n".encode())
			return


		self.send(self.server.rsaKey.publickey().exportKey())
		salt = self.server.hasher.hash(Random.new().read(32))
		self.server.register(self, self.server.hasher.hash(self.server.decryptor.decrypt(self.socket.recv(4096).strip()) + salt.encode()), salt)
		self.authed = True

	def claim(self, msg):
		if not self.authed:
			self.send("You must be registered to claim a channel\r\n".encode())
			return

		if self.channel is None:
			self.send("You must be in a channel to claim it\r\n".encode())
			return

		if self.server.is_channel_claimed(self.channel):
			if self.server.get_channel_owner(self.channel) == self.nick:
				self.send("You already own this channel.\r\n".encode())
			else:
				self.send("This channel is already claimed.\r\n".encode())
			return

		self.server.claim_channel(self.nick, self.channel)
		self.send(f"{self.channel} is now registered to you, {self.nick}\r\n".encode())

	def encrypt_channel(self, msg):
		if self.channel is None:
			self.send("You must be in a channel to encrypt it\r\n".encode())
			return

		if self.server.is_channel_claimed(self.channel):
			if self.server.get_channel_owner(self.channel) == self.nick:
				if msg.lower() == "true":
					self.server.encrypt_channel(self.channel, True)
				elif msg.lower() == "false":
					self.server.encrypt_channel(self.channel, False)
				else:
					state = "" if self.server.is_channel_encrypted(self.channel) else "not "
					self.send(f"/encrypt <true/false>\r\nCurrently this channel is {state}encrypted.\r\n".encode())
			else:
				self.send("You don't own this channel.\r\n".encode())
		else:
			self.send("This channel isn't registered.\r\n".encode())

		

			

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

	## Broadcast a chat message from a client
	def chat(self, client, msg):
		for c in self.clients:
			if (c.channel == client.channel): #Broadcast to everyone inside this channel
				c.send(f"<{client.nick}> {msg}\r\n".encode())


	def broadcast(self, channel, message, exclude=[]):
		for c in self.clients:
			if c not in exclude and c.channel == channel:
				c.send((message + "\r\n").encode())
				
	## Broadcast the arrival of someone
	def arrival(self, client, channel):
		if channel is None:
			client.send("Welcome to NARC Server 0.0.2!\r\n".encode())

		if channel is not None and channel in self.channels: #If there is a MOTD currently set, send it
			owner, motd, _e = self.channels[channel]
			client.send(f"{motd}\r\n".encode())

		for c in self.clients:
			if (c.channel != None and c.channel == channel): # Tell everyone that someone new connected
				c.send(f"Welcome {client.nick} to {channel}!\r\n".encode())

	## Broadcast the departure
	def departure(self, client):
		for c in self.clients:
			if (c.channel != None and c.channel == client.channel and c != client): # Tell everyone that someone left
				c.send(f"{client.nick} has left {client.channel}..\r\n".encode())
	
	
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
						client.request_pubkey()
					else:
						client.send("Sorry, this channel has been encrypted and now requires you to be registered.\r\n".encode())
						client.channel = None
			owner, motd, _e = self.channels[channel]
			self.channels[channel] = (owner, motd, True)
		else:
			for client in self.clients:
				if client.channel == channel:
					client.send("The channels encryption requirement has been disabled.\r\n".encode())
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
		client.send(f"Congratulations, {client.nick} is now registered to you.\r\n".encode())

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