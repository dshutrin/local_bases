from socket import *
from threading import Thread
from os import getcwd, listdir, mkdir
from cryptography.fernet import Fernet
import json, sqlite3 as sql, base64


class User:
	def __init__(self, ip, level, password):
		self.ip = ip
		self.level = level
		self.password = password
		self.con = None
		self.cur = None

		key = ''
		symbols = {
			'0' : 'Q', '1' : 'W', '2' : 'E', '3' : 'R', '4' : 'T', '5' : 'Y', '6' : 'U', '7' : 'I', '8' : 'O', '9' : 'P',
		}
		p = ip.replace('.', '')
		i = 0
		key = ''
		while len(key) != 32:
			key = f'{key}{symbols[p[i]]}'
			i += 1
			if i == len(p):
				i = 0
		key = key.encode()
		self.key = base64.urlsafe_b64encode(key)

		if not(ip in listdir(getcwd())):
			mkdir(ip)

		self.bases = [x.replace('.db', '') for x in listdir(f'{getcwd()}\\{ip}')]


class Server:
	def __init__(self, ip, port):
		self.ser = socket(AF_INET, SOCK_STREAM)
		self.ser.bind((ip, port))
		self.ser.listen(5)

		self.blocked = []
		self.users = []


	def save(self):
		data = {}
		for user in self.users:
			data.update({user.ip : [user.level, user.password]})
		data = json.dumps(data)
		data = json.loads(str(data))
		with open('data.json', 'w', encoding='utf-8') as file:
			json.dump(data, file, indent=4)


	def load(self):
		data = None
		with open('data.json', 'r', encoding='utf-8') as file:
			data = json.load(file)
		for ip in data:
			self.users.append(User(ip, data[ip][0], data[ip][1]))


	def get_user(self, ip):
		for user in self.users:
			if user.ip == ip:
				return user
		return None


	def sender(self, user, key, text):
		f = Fernet(key)
		try:
			text = text.encode()
			user.send(f.encrypt(text))
		except Exception as e:
			print('Client disconnected!')


	def get_msg(self, user, key):
		data = user.recv(1024)
		f = Fernet(key)
		data = f.decrypt(data)
		return data.decode()



	def auth(self, user, addr):

		user_ip = addr[0]
		user_port = addr[1]

		if not(user_ip in self.blocked):#Если пользователь не заблокирован

			this_user = self.get_user(addr[0])

			if this_user == None:
				self.users.append(User(addr[0], 'low level user', 'root'))
				self.save()
				this_user = self.get_user(addr[0])

			if this_user.password != '':
				self.sender(user, this_user.key, 'Type you password.')
				try:
					user_password = self.get_msg(user, this_user.key)
				except Exception as e:
					user_password = None

				if user_password == this_user.password:
					self.sender(user, this_user.key, 'Access is allowed!')
					self.listen(user, addr)

				else:
					self.sender(user, this_user.key, 'Access denied!')
					user.close()

			else:
				self.sender(user, this_user.key, 'Access is allowed!')
				self.listen(user, addr)

		else:
			self.sender(user, this_user.key, 'Access denied!')
			user.close()


	def start_server(self):
		while True:
			user, addr = self.ser.accept()
			Thread(target=self.auth, args=(user, addr, )).start()


	def listen(self, user, addr):
		is_work = True
		while is_work:

			try:
				data = self.get_msg(user, self.get_user(addr[0]).key)
			except Exception as e:
				print('Client disconnected!')
				data = ''
				is_work = False

			if len(data) > 0:
				msg = data

				if msg in ('disconnect', 'exit'):
					print('Client disconnected!')
					user.close()
					is_work = False
				
				else:
					# user message processing

					this_user = self.get_user(addr[0])
					if this_user:

						if msg == 'get access level':
							self.sender(user, this_user.key, this_user.level)


						elif msg == 'get my bases':
							ans = '\n'.join([x.replace('.db', '') for x in listdir(f'{getcwd()}\\{addr[0]}')])
							ans = ans.strip()

							if ans.replace('\n', ''):
								self.sender(user, this_user.key, ans)
							else:
								self.sender(user, this_user.key, 'You have not bases!')


						elif msg.startswith('create base '):
							base_name = f"{msg.replace('create base ', '', 1).strip()}.db"
							path = str(f'{getcwd()}\\{addr[0]}\\{base_name}')

							if base_name != '.db':
								if not(base_name in listdir(f'{getcwd()}\\{addr[0]}')):
									with open(path, 'w') as base:
										base.close()
									this_user.bases.append(base_name.replace('.db', ''))
									self.sender(user, this_user.key, 'Base created!')
								else:
									self.sender(user, this_user.key, 'Base is exists!')
							else:
								self.sender(user, this_user.key, 'Error base name!')


						elif msg.startswith('set password '):
							password = msg.replace('set password ', '', 1)
							this_user.password = password
							self.sender(user, this_user.key, 'You password updated!')


						elif msg.startswith('connect to '):
							base_name = msg.replace('connect to ', '', 1)
							if base_name in this_user.bases:
								
								this_user.con = sql.connect(f"{getcwd()}\\{addr[0]}\\{base_name}.db")
								this_user.cur = this_user.con.cursor()

								self.sender(user, this_user.key, f'You are connected to base <{base_name}>!')

							else:
								self.sender(user, this_user.key, f'You have not base <{base_name}>!')


						elif msg == 'close base':
							if this_user.con != None:
								
								this_user.cur.close()
								this_user.con.close()
								this_user.cur = None
								this_user.con = None

								self.sender(user, this_user.key, 'You are disconnected from base!')

							else:
								self.sender(user, this_user.key, 'You are not connected to base now!')


						else:
							if (this_user.con != None) and (this_user.cur != None):
								try:
									data = str([x for x in this_user.cur.execute(msg)])
									this_user.con.commit()
									if data != '[]':
										self.sender(user, this_user.key, data)
									else:
										self.sender(user, this_user.key, 'default answer')
								except Exception as e:
									self.sender(user, this_user.key, f'Error: {str(e)}!')
							else:
								self.sender(user, this_user.key, 'You are not connected to base now!')


					else:
						user.close()
						print('Client disconnected!')
						is_work = False

				self.save()

			else:
				user.close()
				print('Client disconnected!')
				is_work = False


if __name__ == '__main__':
	serv = Server('192.168.180.1', 7000)
	serv.load()
	serv.start_server()