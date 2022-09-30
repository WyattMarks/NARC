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

from rich import print
import time

import readchar

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
		self.history = []

		self.color_names = {"Anonymous": '[#000000]'}
		self.msg = ''
		self.cursor = 0

	def get_input(self, prefix=""):
		sys.stdout.write(prefix)
		cursor = 0
		self.msg = ''
		history_position = -1
		c = ''
		while c != readchar.key.ENTER:
			c = readchar.readkey()

			if c == readchar.key.UP:
				history_position += 1
				if history_position < len(self.history):
					self.print_prefix()
					print("[white]" + self.history[len(self.history) - history_position - 1], end='')
					cursor = len(self.history[len(self.history) - history_position - 1])
				else:
					history_position = len(self.history) - 1
				continue
			
			if c == readchar.key.DOWN:
				history_position -= 1
				self.print_prefix()
				if history_position > -1:
					print("[white]" + self.history[len(self.history) - history_position - 1], end='')
					cursor = len(self.history[len(self.history) - history_position - 1])
				else:
					history_position = -1
					print("[white]" + self.msg, end='')
					cursor = len(self.msg)
				continue

			if c == readchar.key.LEFT:
				cursor -= 1
				if cursor < 0:
					cursor = 0
				else:
					sys.stdout.write(c)
					sys.stdout.flush()
				continue

			if c == readchar.key.RIGHT:
				cursor += 1
				selected = self.msg if history_position == -1 else self.history[len(self.history) - history_position - 1]
				if cursor > len(selected):
					cursor = len(selected)
				else:
					sys.stdout.write(c)
					sys.stdout.flush()
				continue

			if history_position != -1:
				self.msg = self.history[len(self.history) - history_position - 1]
				history_position = -1

			if c == readchar.key.ENTER:
				continue

			if c == readchar.key.BACKSPACE:
				if cursor > 0:
					self.msg = self.msg[:cursor-1] + self.msg[cursor:]
					cursor -= 1
					sys.stdout.write('\b \b' + self.msg[cursor:] + ' ')
					for i in range(len(self.msg[cursor:]) + 1):
						sys.stdout.write(readchar.key.LEFT)
					sys.stdout.flush()
				continue
			elif self.waiting_for_password:
				sys.stdout.write('*')
			else:
				sys.stdout.write(c + self.msg[cursor:])
				for i in range(len(self.msg[cursor:])):
					sys.stdout.write(readchar.key.LEFT)
			self.msg = self.msg[:cursor] + c + self.msg[cursor:]
			cursor += 1
			self.cursor = cursor
			sys.stdout.flush()

		if not self.waiting_for_password:
			self.history.append(self.msg)

		return self.msg


	def connect(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.connect((self.ip, self.port))

	def register_nick(self, nick):
		if nick not in self.color_names:
			import random
			self.color_names[nick] = f"[#{random.randrange(0x1000000):06x}]"

	def print_prefix(self):
		sys.stdout.write('\033[2K\033[1G')
		if self.channel is not None:
			if self.channel_encrypted:
				print(f"[white][[dodger_blue2]{self.channel}[white]]",end='')
				print(f" <{self.color_names[self.nick]}{self.nick}[white]>: ", end="")
			else:
				print(f"\[{self.channel}] <{self.color_names[self.nick]}{self.nick}[white]>: ", end="")
		else:
			print(f'<{self.color_names[self.nick]}{self.nick}[white]>: ', end='')

		print(f"[white]{self.msg}", end='')
		for i in range(len(self.msg[self.cursor:])):
			sys.stdout.write(readchar.key.LEFT)

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

				if response.startswith("-----BEGIN PUBLIC KEY-----"):
						self.encryptor = PKCS1_OAEP.new(RSA.importKey(response))
						self.waiting_for_password = True
						sys.stdout.write('\033[2K\033[1G')
						print("Password: ", end="")
						continue

				for response in response.splitlines():
					if response.startswith("PUBKEYREQ"):
						self.socket.send(self.rsaKey.publickey().exportKey())
						continue
					
					if response.startswith(f"{self.nick} is now known as ") or response.startswith("Welcome back, "):
						self.nick = response.strip().replace(f"{self.nick} is now known as ", "").replace("Welcome back, ", "")
						self.nick = self.nick[0:len(self.nick)-1]
						self.register_nick(self.nick)

					if response.startswith("You are now known as "):
						self.nick = response.strip().replace("You are now known as ", "")
						self.nick = self.nick[0:len(self.nick)-1]
						self.register_nick(self.nick)
						self.print_prefix()
						continue

					if response.startswith("Joining #"):
						self.channel = "#" + response.replace("Joining #", "").replace("...", "")
						self.channel_encrypted = False

					if response.startswith("This channel is encrypted with AES."):
						self.channel_encrypted = True

					if response.startswith("<"):
						self.register_nick(response[1:response.find('>')])
						response = "<" + self.color_names[response[1:response.find('>')]] + response[1:response.find('>')] +"[white]>" + response[response.find('>') + 1:]
					
					sys.stdout.write('\033[2K\033[1G')
					sys.stdout.flush()
					print(time.strftime('[white][[green1]%H:%M:%S[white]] ') + response)
				self.print_prefix()

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
				self.print_prefix()
				message = self.get_input()
				if len(message) > 0:
					if self.waiting_for_password:
						password = self.encryptor.encrypt(message.encode())
						self.socket.send(password)
						self.waiting_for_password = False
					elif message.startswith("/"): #If it starts with / then it is a command, and we should not prepend /chat
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
	server = "wyattmarks.com"
	#server = "localhost"
	port = 0xBEEF
	if len(sys.argv) >= 2:
		server = sys.argv[1]
	if len(sys.argv) >= 3:
		port = sys.argv[2]


	c = Client(server, port)

	try:
		c.connect()
	except ConnectionRefusedError:
		print(f"Unable to connect to {server}")
		exit(0)

	print_thread = threading.Thread(target=c.print_responses) #Put this in a thread so the socket.recv call doesn't block us from sending input
	print_thread.setDaemon(True) #Make it a deamon so that the program doesn't hang around waiting for the thread
	print_thread.start()
	c.handle_input()