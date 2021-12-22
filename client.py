from socket import *
from getpass import getpass
from cryptography.fernet import Fernet
import base64

class Client:
	def __init__(self, ip, port):
		self.cli = socket(AF_INET, SOCK_STREAM)
		self.cli.connect(
			(ip, port)
		)

		symbols = {
			'0' : 'Q', '1' : 'W', '2' : 'E', '3' : 'R', '4' : 'T', '5' : 'Y', '6' : 'U', '7' : 'I', '8' : 'O', '9' : 'P',
		}
		p = self.cli.getsockname()[0].replace('.', '')
		i = 0
		key = ''
		while len(key) != 32:
			key = f'{key}{symbols[p[i]]}'
			i += 1
			if i == len(p):
				i = 0
		key = key.encode()
		key = base64.urlsafe_b64encode(key)
		self.f = Fernet(key)


	def sender(self, text):
		text = text.encode()
		text = self.f.encrypt(text)
		try:
			self.cli.send(text)
		except Exception as e:
			pass


	def get_msg(self):
		data = self.cli.recv(1024)
		data = self.f.decrypt(data)
		msg = data.decode()
		return msg


	def auth(self):

		server_answer = self.get_msg()

		if server_answer == 'Type you password.':
			self.sender(getpass())

			answer = self.get_msg()

			if answer == 'Access is allowed!':
				return 1

			if answer == 'Access denied!':
				return 0

		elif server_answer == 'Access is allowed!':
			return 1

		elif server_answer == 'Access denied!':
			return 0


	def connect(self):

		connection = self.auth()
		if connection:
			print('Connected!')
			self.listen()
		else:
			print('Access denied!')


	def listen(self):
		while True:
			data = input('Enter request to server: ')
			if not(data in ('disconnect', 'exit')):
				try:
					self.sender(data)
					msg = self.get_msg()
				except Exception as e:
					print(e)
					print('Server disconnected!')
					msg = 'Server disconnected!'

				if msg != 'default answer':
					if msg == 'Server disconnected!':
						exit()
	
					else:
						# server message processing
						text1 = msg.split('\n')
						text = '\t'
						for i in text1:
							text = f'{text}{i}\n\t'
						text = text.rstrip()
	
						print(f'SERVER ANSWER:\n{text}')


			else:
				self.sender('disconnect')
				self.cli.close()
				print('Exiting...')
				exit()

Client('127.0.0.1', 7000).connect()
input()