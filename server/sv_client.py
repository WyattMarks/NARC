## Super simple relay chat protocol.
#  This is the server implmentation. 
#  NARC - Not Another Relay Chat 
#  https://github.com/wyattmarks/narc


from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto import Random
from base64 import b64encode, b64decode


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

		self.rsa_encryptor = None

		self.aes_key = None

		self.encrypt_queue = [] #in case we try to send a message before getting their pubkey

	## Start the connection. Blocks until connection ends
	def begin(self):
		self.connected = True

		new_nick = self.nick
		while not self.server.nick_available(new_nick):
			new_nick = self.nick + str( int.from_bytes(Random.new().read(2), byteorder='big', signed=False) )
		self.nick = new_nick

		# Let the client know the connection was successful
		self.server.arrival(self, None)

		while self.connected:
			try:
				msg = self.socket.recv(4096)

				if msg == b'':
					raise BrokenPipeError

				if msg[0:10].decode() == "ENCRYPTED:":
					msg = self.decrypt(msg[10:])
				msg = msg.decode()
				
				print(f"{self.nick} ({self.ip})> {msg.strip()}")

				if msg.startswith("-----BEGIN PUBLIC KEY-----"):
					self.rsa_encryptor = PKCS1_OAEP.new(RSA.importKey(msg))
					self.send_channel_key()
				else:
					valid = False
					for command in self.commands:
						if msg.startswith(command + " "):
							self.commands[command](msg.strip().replace(command + " ", "")) #Call the callback for this command from the dictionary
							valid = True
							break
					
					if not valid:
						self.send("Error, command not found.")

			except BrokenPipeError: #Broken pipe means that client disconnected, let people know
				print(f"{self.nick} has disconnected..")
				self.server.disconnect(self) #handle disconnection
				self.connected = False #let the infinite loop stop
				break
			except Exception as e:
				print(f"Exception on client {self.nick}({self.ip}): {e.with_traceback(None)}")
			
		self.socket.close() #close the socket after the infinite loop ends

	def send(self, data, encryption_override=None):
		if type(data) == str:
			data = (data + "\r\n").encode()

		if (encryption_override != False) and ((encryption_override is not None and encryption_override) or (self.channel is not None and self.server.is_channel_encrypted(self.channel))):
			if self.aes_key is None:
				self.request_pubkey() #shouldnt happen, but eh? ask again I guess
				self.encrypt_queue.append(data)
			else:
				for msg in self.encrypt_queue:
					self.socket.send("ENCRYPTED:".encode() + self.encrypt(msg))
				self.encrypt_queue = []
				self.socket.send("ENCRYPTED:".encode() + self.encrypt(data))
		else:
			self.socket.send(data)

	def request_pubkey(self):
		self.send("PUBKEYREQ")

	# Sends the AES key to the client, encrypted assymetrically with their public key
	def send_channel_key(self):
		if self.rsa_encryptor is None:
			raise Exception('RSA Public Key hasn\'t been receieved yet')
		self.aes_key = Random.new().read(32) # 32 bytes == 256 bit key
		self.send( 'CHANNELKEY'.encode() + self.rsa_encryptor.encrypt(self.aes_key), encryption_override=False )

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


	## Join the given channel
	def join_channel(self, msg):
		if msg.startswith("#"): # Just like IRC, channels start with #
			if self.server.is_channel_encrypted(msg):
				if self.authed:
					self.send(f"Joining {msg}...\r\nThis channel is encrypted with AES.")
					if self.rsa_encryptor is None:
						self.request_pubkey()
				else:
					self.send("You must be registered to join this channel because it is encrypted.")
					return
			else:
				self.send(f"Joining {msg}...")

			self.server.arrival(self, msg) # Tell anyone in the channel someone joined
			self.server.departure(self) # Tell anyone in the old channel that someone left
			self.channel = msg
		else:
			self.send(f"Channel names must begin with a #")
		
	## Broadcast a message to the channel the client is in
	def send_chat(self, msg):
		if msg != "/chat":
			if self.channel != None:
				self.server.broadcast(self.channel, f"<{self.nick}> {msg}") # Broadcast the chat message in this channel
			else:
				self.send("You must join a channel first (/join)")
		else:
			self.send("You must provide a message to send after /chat")

	## Set the client's nick name
	def set_nick(self, msg):
		if self.server.is_channel_encrypted(self.channel):
			self.send("You cannot switch names in an encrypted chat.")
			return

		if msg != "/nick":
			if self.server.is_nick_registered(msg):
				self.send(f"Sorry, {msg} is registered. If this is your nick, use /auth <nick> to login")
				return

			if self.server.nick_available(msg):
				if self.authed:
					self.send(f"You have been logged out, {self.nick}")
					self.authed = False
				self.authed = False
				self.server.broadcast(self.channel, f"{self.nick} is now known as {msg}!")
				self.nick = msg
			else:
				self.send(f"Sorry, {msg} is already in use.")
		else:
			self.send("You must give a nickname to use after /nick")

	## The the current channel's nick name
	def set_motd(self, msg):
		if msg == "/motd":
			self.send((self.server.get_motd(self.channel) + "\r\n").encode())
			return
		
		if self.channel is None:
			self.send("You must be a channel to see a channel's MOTD..")
			return

		if not self.server.is_channel_claimed(self.channel):
			self.send("This channel is not claimed, and therefore has no MOTD. Claim it with /claim!")
			return

		if not self.authed:
			self.send((self.server.get_motd(self.channel) + "\r\n").encode())
			return

		if self.nick != self.server.get_channel_owner(self.channel):
			self.send((self.server.get_motd(self.channel) + "\r\n").encode())
			return
		
		self.server.set_motd(self, msg)
		self.send("Channel MOTD set.")

			

	## Ping
	def pong(self, msg):
		self.send("Pong!")

	## End the connection
	def quit(self, msg):
		self.send("Goodbye!")
		self.server.disconnect(self)
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
			self.send("Join a channel to see who's online in that channel")

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
			self.send("You must provide a nickname to login to")
			return

		if not self.server.is_nick_registered(msg):
			self.send("This nickname is not registered")
			return

		if self.authed:
			self.send("You are already logged in..")
			return


		self.send(self.server.rsaKey.publickey().exportKey())
		if self.server.auth(msg, self.server.decryptor.decrypt(self.socket.recv(4096).strip()).strip() + self.server.get_salt(msg).encode()):
			self.nick = msg
			self.send(f"Welcome back, {self.nick}!")
			self.server.broadcast(self.channel, f"{self.nick} has logged in!\r\n", exclude=[self])
			self.authed = True
		else:
			self.send("Sorry, that is not the correct password.")
			

	## Register a nick with a password
	def register(self, msg):
		if self.server.is_nick_registered(self.nick):
			self.send("This nickname is already registered")
			return

		if self.nick == "Anonymous":
			self.send("You must first select a nick name (/nick)")
			return


		self.send(self.server.rsaKey.publickey().exportKey())
		salt = Random.new().read(32).decode('latin-1')

		self.server.register(self, self.server.hasher.hash(self.server.decryptor.decrypt(self.socket.recv(4096).strip()) + salt.encode()), salt)
		self.authed = True

	def claim(self, msg):
		if not self.authed:
			self.send("You must be registered to claim a channel")
			return

		if self.channel is None:
			self.send("You must be in a channel to claim it")
			return

		if self.server.is_channel_claimed(self.channel):
			if self.server.get_channel_owner(self.channel) == self.nick:
				self.send("You already own this channel.")
			else:
				self.send("This channel is already claimed.")
			return

		self.server.claim_channel(self.nick, self.channel)
		self.send(f"{self.channel} is now registered to you, {self.nick}")

	def encrypt_channel(self, msg):
		if self.channel is None:
			self.send("You must be in a channel to encrypt it")
			return

		if self.server.is_channel_claimed(self.channel):
			if self.server.get_channel_owner(self.channel) == self.nick:
				if msg.lower() == "true":
					self.server.encrypt_channel(self.channel, True)
				elif msg.lower() == "false":
					self.server.encrypt_channel(self.channel, False)
				else:
					state = "" if self.server.is_channel_encrypted(self.channel) else "not "
					self.send(f"/encrypt <true/false>\r\nCurrently this channel is {state}encrypted.")
			else:
				state = "" if self.server.is_channel_encrypted(self.channel) else "not "
				self.send(f"Currently this channel is {state}encrypted.")
		else:
			self.send("This channel isn't registered.")
