#!/usr/bin/python3
import socket,re,uuid,time
########################
# Some Global Variables
serversocket=''
host = socket.gethostname() 
mac=':'.join(re.findall('..','%012x'%uuid.getnode()));

##########################

# Server Socket Initialization
def initServer(ip,port):
	global serversocket
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serversocket.bind(('0.0.0.0', port)) #Host will be replaced/substitued with IP, if changed and not running on host
	serversocket.listen(5)
	print("Client A Starting...")
	print("My Hostname: {}".format(host))
	print("My Mac: {}".format(mac))
	print("##################################################")
	time.sleep(2)

########################
# this is to recieve data from client socket
def recvMessage():
	global clientsocket
	data = clientsocket.recv(1024);
	print("Message Recieved from client B")
	while True:
		if data:
			print("Cipher Text: {}".format(str(data,"utf-8")))
			print("####################################################")
			decryptCipher(str(data,"utf-8").split("--")[0]);

		data=None

#########################

# this is to send the data to client socket
def sendMessage():
	global clientsocket
	#Starting the connection 
	clientsocket,address = serversocket.accept()
	#Message sent to client after successful connection
	message = host+"--"+mac+ "\r\n"
	encmessage = encryptText(message.split("--")[0])+"--"+message.split("--")[1]
	clientsocket.send(bytes(encmessage,"utf-8"))
	print("Message {} sent to client B".format(encmessage))
	print("##################################################")
	time.sleep(2)

# Method Which takes ciphertext as input and generates plaintext as output
########################
def decryptCipher(CIPHERTEXT):
	LETTERS = 'abcdefghijklmnopqrstuvwxyz'
	for key in range(len(LETTERS)):
		PLAINTEXT = ''
		for symbol in CIPHERTEXT:
			if symbol in LETTERS:
				num = LETTERS.find(symbol)
				num = num - key

				if num < 0:
					num = num + len(LETTERS)
				PLAINTEXT = PLAINTEXT + LETTERS[num]
			else:
				PLAINTEXT = PLAINTEXT + symbol
		print("KEY #{} : {}".format(key, PLAINTEXT))

############################

# Method which takes plaintext as input and returns ciphertext as output
def encryptText(PLAINTEXT):
	key=0;
	LETTERS = 'abcdefghijklmnopqrstuvwxyz'
	CIPHERTEXT=''
	# Key computation logic
	for ch in PLAINTEXT:
		key+=ord(ch)
	key=(round(key/len(PLAINTEXT)))%26 
	

	for symbol in PLAINTEXT:
		if symbol in LETTERS:
			num = LETTERS.find(symbol)
			num = num + key

			if num > 25:
				num = num - len(LETTERS)
			CIPHERTEXT = CIPHERTEXT + LETTERS[num]
		else:
				CIPHERTEXT = CIPHERTEXT + symbol
	
	return CIPHERTEXT

# Entry point to the server program
###########################
def main():
	initServer('0.0.0.0',1337)
	sendMessage()
	recvMessage()

#########################
if __name__ == '__main__':
	main()