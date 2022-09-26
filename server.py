## Super simple relay chat protocol.
#  This is the server implmentation. 
#  NARC - Not Another Relay Chat 


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
		}

	## Start the connection. Blocks until connection ends
	def begin(self):
		self.connected = True

		# Let the client know the connection was successful
		self.server.arrival(self, None)

		while self.connected:
			try:
				msg = self.socket.recv(4096).decode()
				
				print(f"{self.nick} ({self.ip})> {msg.strip()}")

				valid = False
				for command in self.commands:
					if msg.startswith(command + " "):
						self.commands[command](msg.strip().replace(command + " ", "")) #Call the callback for this command from the dictionary
						valid = True
						break
				
				if not valid:
					self.socket.send("Error, command not found.\r\n".encode())

			except BrokenPipeError: #Broken pipe means that client disconnected, let people know
				print(f"{self.nick} has disconnected..")
				self.server.disconnect(self) #handle disconnection
				self.connected = False #let the infinite loop stop
				break
			except Exception as e:
				print(f"Exception on client {self.nick}({self.ip}): {e}")
			
		self.socket.close() #close the socket after the infinite loop ends

	## Join the given channel
	def join_channel(self, msg):
		if msg.startswith("#"): # Just like IRC, channels start with #
			self.socket.send(f"Joining {msg}...\r\n".encode())
			self.server.arrival(self, msg) # Tell anyone in the channel someone joined
			self.server.departure(self) # Tell anyone in the old channel that someone left
			self.channel = msg
		else:
			self.socket.send(f"Channel names must begin with a #\r\n".encode())
		
	## Broadcast a message to the channel the client is in
	def send_chat(self, msg):
		if self.channel != None:
			self.server.chat(self, msg) # Broadcast the chat message in this channel
		else:
			self.socket.send("You must join a channel first (/join)\r\n".encode())

	## Set the client's nick name
	def set_nick(self, msg):
		if msg != "/nick":
			if self.server.is_nick_registered(msg):
				self.socket.send(f"Sorry, {msg} is registered. If this is your nick, use /auth <nick> to login\r\n".encode())
				return

			if self.server.nick_available(msg):
				self.authed = False
				self.server.broadcast(self.channel, f"{self.nick} is now known as {msg}!")
				self.nick = msg
			else:
				self.socket.send(f"Sorry, {msg} is already in use.\r\n".encode())
		else:
			self.socket.send("You must give a nickname to use after /nick\r\n".encode())

	## The the current channel's nick name
	def set_motd(self, msg):
		if msg == "/motd":
			self.socket.send("You must give a MOTD to set\r\n".encode())
			return
		
		if self.channel is None:
			self.socket.send("You must be a channel to set a channel's MOTD..\r\n".encode())
			return

		if not self.server.is_channel_claimed(self.channel):
			self.socket.send("This channel is not claimed. Claim it with /claim\r\n".encode())
			return

		if not self.authed:
			self.socket.send("You must be logged in as the owner of this channel. /auth <nick>\r\n".encode())
			return

		if self.nick != self.server.get_channel_owner(self.channel):
			self.socket.send("You are not the owner of this channel!\r\n".encode())
			return
		
		self.server.set_motd(self, msg)
		self.socket.send("Channel MOTD set.\r\n".encode())

			

	## Ping
	def pong(self, msg):
		self.socket.send("Pong!\r\n".encode())

	## End the connection
	def quit(self, msg):
		self.socket.send("Goodbye!\r\n".encode())
		self.server.departure(self)
		self.connected = False

	## List the currently connection clients in this channel
	def online(self, msg):
		if self.channel != None:
			clients = self.server.get_online(self.channel)
			message = f"There are currently {len(clients)} people online in {self.channel}\r\n"
			for c in clients:
				message += f"\t{c.nick}\r\n"
			self.socket.send(message.encode())

		else:
			self.socket.send("Join a channel to see who's online in that channel\r\n".encode())

	def list_channels(self, msg):
		message = f"There are currently {len(self.server.channels)} registered channels\r\n"
		for c in self.server.channels:
			message += f"\t{c}\r\n"
		self.socket.send(message.encode())


	## List the command dictionary
	def help(self, msg):
		message = "Available Commands:\r\n"
		for cmd in self.commands:
			message += f"\t{cmd}\r\n"

		self.socket.send(message.encode())

	## Login with password
	def auth(self, msg):
		if msg == "/auth":
			self.socket.send("You must provide a nickname to login to\r\n".encode())
			return

		if not self.server.is_nick_registered(msg):
			self.socket.send("This nickname is not registered\r\n".encode())
			return

		if self.authed:
			self.socket.send("You are already logged in..\r\n".encode())
			return


		self.socket.send(self.server.rsaKey.publickey().exportKey())
		if self.server.auth(msg, self.server.decryptor.decrypt(self.socket.recv(4096).strip()) + self.server.get_salt(msg).encode()):
			self.nick = msg
			self.socket.send(f"Welcome back, {self.nick}!\r\n".encode())
			self.authed = True
		else:
			self.socket.send("Sorry, that is not the correct password.\r\n".encode())
			

	## Register a nick with a password
	def register(self, msg):
		if self.server.is_nick_registered(self.nick):
			self.socket.send("This nickname is already registered\r\n".encode())
			return

		if self.nick == "Anonymous":
			self.socket.send("You must first select a nick name (/nick)\r\n".encode())
			return


		self.socket.send(self.server.rsaKey.publickey().exportKey())
		salt = self.server.hasher.hash(Random.new().read(32))
		self.server.register(self, self.server.hasher.hash(self.server.decryptor.decrypt(self.socket.recv(4096).strip()) + salt.encode()), salt)
		self.authed = True

	def claim(self, msg):
		if not self.authed:
			self.socket.send("You must be registered to claim a channel\r\n".encode())
			return

		if self.channel is None:
			self.socket.send("You must be in a channel to claim it\r\n".encode())

		self.server.claim_channel(self.nick, self.channel)
		self.socket.send(f"{self.channel} is now registered to you, {self.nick}\r\n".encode())

		

			

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
			self.save_passwords()

	def save_channels(self):
		try:
			f = open("channels.json", "w")
			f.write(json.dumps(self.channels))
			f.close()
		except Exception as e:
			print(f"Error writing auth.json.. {e}")
		
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
				c.socket.send(f"<{client.nick}> {msg}\r\n".encode())


	def broadcast(self, channel, message):
		for c in self.clients:
			if c.channel == channel:
				c.socket.send((message + "\r\n").encode())
				
	## Broadcast the arrival of someone
	def arrival(self, client, channel):
		if channel is None:
			client.socket.send("Welcome to NARC Server 0.0.2!\r\n".encode())

		if channel is not None and channel in self.channels: #If there is a MOTD currently set, send it
			owner, motd = self.channels[channel]
			client.socket.send(f"{motd}\r\n".encode())

		for c in self.clients:
			if (c.channel != None and c.channel == channel): # Tell everyone that someone new connected
				c.socket.send(f"Welcome {client.nick} to {channel}!\r\n".encode())

	## Broadcast the departure
	def departure(self, client):
		for c in self.clients:
			if (c.channel != None and c.channel == client.channel and c != client): # Tell everyone that someone left
				c.socket.send(f"{client.nick} has left {client.channel}..\r\n".encode())
	
	
	def is_channel_claimed(self, channel):
		for c in self.channels:
			if channel == c:
				return True

		return False

	def get_channel_owner(self, channel):
		owner, motd = self.channels[channel]
		return owner

	def claim_channel(self, nick, channel):
		self.channels[channel] = (nick, f"Welcome to {channel}")
		self.save_channels()


	## Set a channel's MOTD
	def set_motd(self, client, motd): 
		self.channels[client.channel] = (client.nick, motd)
		self.save_channels()

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
		client.socket.send(f"Congratulations, {client.nick} is now registered to you.\r\n".encode())

	def auth(self, nick, password):
		(hash, salt) = self.passwords[nick]
		return self.hasher.verify(hash, password)







if __name__ == "__main__":
	server = Server(host, port)
	try:
		server.start()
	except:
		server.stop()