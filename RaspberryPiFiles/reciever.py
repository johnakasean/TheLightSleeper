import socket
import subprocess
#this is the pi that is recieving so it keeps its own ip address
UDP_IP = "192.168.1.13"
#this gives the two pis access to the same port to connect.
UDP_PORT = 1180

sock = socket.socket(socket.AF_INET, # Allows the pi to connect to Internet to link
                     socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # this line was important as if the script was restarted, without
#this line, the port would stay open meaning it wasnt able to be reused when script was restarted.
sock.bind((UDP_IP, UDP_PORT))#grabs the ip address and port and binds them

while True: #this is what will show message recieved from the other pi
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print "received message:", data 
    try: #this try will run when message is recieved and will start the turnoff script to switch light off.
	subprocess.call(["python","turnoff.py"])
	raise SystemExit()
    except KeyboardInterrupt:
	print "Quit"



