#!/usr/bin/python3
'''
- This is the client program considered as peer two.
- It recieved the data from the server in the CipherText form.
- Launches Bruteforce attack to crack the secret

'''


# Some important Libraries
import socket,re,uuid,time

# Some Global Variables
###########################################
host = socket.gethostname() # Fetches hotname
mac=':'.join(re.findall('..','%012x'%uuid.getnode())); # For fetching MAC Address
clientsocket=''
#########################################

# This function take care of TCP client socket initialization and initial display
def initClient(ip,port):
	global clientsocket
	print("Client B Starting...")
	print("My Hostname: {}".format(host))
	print("My Mac: {}".format(mac))
	print("##################################################")
	time.sleep(2)
	clientsocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	clientsocket.connect((ip, port))
#########################

# this method takes ciphertext as input and produce plain text as output

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

#############################

# This function takes plain text as input and produce ciphertext as output based on the key formula
def encryptText(PLAINTEXT):
	key=0;
	LETTERS = 'abcdefghijklmnopqrstuvwxyz'
	CIPHERTEXT=''
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


#################

# This is to handle the two way traffic and recieve data from the server
def recvMessage():
	global clientsocket
	message = clientsocket.recv(1024)
	print("Message Recieved from client A: ")
	print("CIPHERTEXT: {}".format(str(message,"utf-8")))
	print("####################################################")
	decryptCipher(str(message,"utf-8").split("--")[0])
	message=""
	print("##################################################")
	time.sleep(2)

########################

# this is to send data to the server
def sendMessage():
	global clientsocket
	data = host+"--"+mac+"\r\n"
	encdata = encryptText(data.split("--")[0])+"--"+data.split("--")[1]
	print("message: {} sent to client A".format(encdata))
	while True:
		if data:
			clientsocket.send(bytes(encdata,"utf-8"))
		data=None
##########################

# This is the program entry point
def main():
	initClient('193.37.215.126',1337)
	recvMessage()
	sendMessage()

	#clientsocket.close()
##############################

if __name__ == '__main__':
	main()