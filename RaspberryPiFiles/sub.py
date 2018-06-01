
import paho.mqtt.client as paho
import os
import ssl
import subprocess #starts another script

#connection to aws from reaspberry pi
awshost = "akhn5y05p1uuq.iot.eu-west-1.amazonaws.com"
awsport = 8883
clientId = "raspberrypi"
thingName = "raspberrypi"
caPath = "rootCA.crt"
certPath = "087aade7ba-certificate.pem.crt"
keyPath = "087aade7ba-private.pem.key"

#notifys user has connected
def on_connect(client, userdata, flags, rc):
    print("Connection returned result: " + str(rc) )
    # subscribing with on_connect means if link broken it will reestablish connection
    client.subscribe("#" , 1 )
#this is message from the app that they wish to activate the light
def on_message(client, userdata, msg):
    print("Phone App: "+str(msg.payload))
    try:#this try then says if message is recieaved then it will start lowlevel.py which is the light
	subprocess.call(["python","lowlevel.py"])
	raise SystemExit()
    except KeyboardInterrupt:
	print "Quit"


mqttc = paho.Client()
mqttc.on_connect = on_connect
mqttc.on_message = on_message


#this grabs the certificates which are in the same folder as this file so it can establish connection using private key, the root
# and the certificate recieved when it is created on aws.


mqttc.tls_set(caPath, certfile=certPath, keyfile=keyPath, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLSv1_2, ciphers=None)

mqttc.connect(awshost, awsport, keepalive=60)

mqttc.loop_forever()

