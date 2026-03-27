import socket

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect(('localhost', 8089))
print('client connection successful')
clientSocket.send('hello')
