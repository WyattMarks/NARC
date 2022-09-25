## Super simple relay chat protocol.
#  This is the server implmentation. 
#  NARC - Not Another Relay Chat 
#  Currently there is no authentication or permissions
#  Eventually there should be accounts with passwords associated to nicknames (optional of course)
#  If an account is authed it will be able to "claim" a channel - and then will be the only account able to set MOTD
#            Eventually add ban / kick options as well

import socket
import threading

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
		self.channel = None

		self.commands = { ## Command dictionary makes parsing input much easier
			"/join": self.join_channel,
			"/chat": self.send_chat,
			"/nick": self.set_nick,
			"/motd": self.set_motd,
			"/ping": self.pong,
			"/quit": self.quit,
			"/exit": self.quit,
			"/online": self.online,
			"/help": self.help,
		}

	## Start the connection. Blocks until connection ends
	def begin(self):
		self.connected = True

		# Let the client know the connection was successful
		self.server.arrival(self, None)

		while self.connected:
			try:
				msg = self.socket.recv(1024).decode()
				
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
			if self.server.nick_available(msg):
				self.nick = msg
				self.socket.send(f"Hello there, {msg}!\r\n".encode())
			else:
				self.socket.send(f"Sorry, {msg} is already in use.\r\n".encode())
		else:
			self.socket.send("You must give a nickname to use after /nick\r\n".encode())

	## The the current channel's nick name
	def set_motd(self, msg):
		if self.channel != None:
			self.server.set_motd(self.channel, msg)
			self.socket.send(f"MOTD set for {self.channel}\r\n".encode())
		else:
			self.socket.send("You must be a channel to set a channel's MOTD..\r\n")

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

	## List the command dictionary
	def help(self, msg):
		message = "Available Commands:\r\n"
		for cmd in self.commands:
			message += f"\t{cmd}\r\n"

		self.socket.send(message.encode())

## The actual server object
class Server:
	## Must be given an IP and port to listen on
	def __init__(self, host, port):
		self.host = host
		self.port = port
		
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create socket object

		self.clients = [] #Empty list for clients
		self.channel_motds = {
			None: "Welcome to NARC Server 0.0.1!"
		} #Dictionary for channel MOTDs. None is the Server's MOTD
		
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

	
	def stop(self):
		self.socket.close() #Close the socket when we stop


	def chat(self, client, msg):
		for c in self.clients:
			if (c.channel == client.channel): #Broadcast to everyone inside this channel
				c.socket.send(f"<{client.nick}> {msg}\r\n".encode())

	def arrival(self, client, channel):
		if channel in self.channel_motds: #If there is a MOTD currently set, send it
			prefix = f"{channel}: " if channel is not None else ""
			client.socket.send(f"{prefix}{self.channel_motds[channel]}\r\n".encode())

		for c in self.clients:
			if (c.channel != None and c.channel == channel): # Tell everyone that someone new connected
				c.socket.send(f"Welcome {client.nick} to {channel}!\r\n".encode())

	def departure(self, client):
		for c in self.clients:
			if (c.channel != None and c.channel == client.channel and c != client):
				c.socket.send(f"{client.nick} has left {client.channel}..\r\n".encode())

	def set_motd(self, channel, motd):
		self.channel_motds[channel] = motd

	def disconnect(self, client):
		self.departure(client)
		self.clients.remove(client)

	def nick_available(self, nick):
		for c in self.clients:
			if c.nick == nick:
				return False

		return True

	def get_online(self, channel):
		clients = []
		for c in self.clients:
			if c.channel == channel:
				clients.append(c)

		return clients







if __name__ == "__main__":
	server = Server(host, port)
	try:
		server.start()
	except:
		server.stop()