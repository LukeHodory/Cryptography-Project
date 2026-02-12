import socket

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.bind(('localhost', 8089))
serverSocket.listen(5) # become a server socket, maximum 5 connections

while True:
    connection, address = serverSocket.accept()
    print('server connection successful')

    buf = connection.recv(64)
    if len(buf) > 0:
        print(buf)
        break
