import paho.mqtt.client as mqtt
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
import ast

broker="broker.mqtt-dashboard.com"

def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("mqtt/rafly")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    enkr = msg.payload.decode("UTF-8")
    msgg = ast.literal_eval(enkr)
    decrypted = decrypt(msgg, "123")
    #change from bytes to string
    w = decrypted.decode('UTF-8') 
    print(msg.topic+" "+w)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("broker.mqtt-dashboard.com", 1883, 60)



# Blocking call that processes network traffic, dispatches callbacks and
# handles reconnecting.
# Other loop*() functions are available that give a threaded interface and a
# manual interface.
client.loop_forever()