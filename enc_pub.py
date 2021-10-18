import paho.mqtt.client as mqtt
import time
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
import json

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected successfully")
    else:
        print("Connect returned result code: " + str(rc))

def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

client = mqtt.Client() #creating new instance
client.on_connect = on_connect

broker="broker.mqtt-dashboard.com"
#client.tls_set(tls_version=mqtt.ssl.PROTOCOL_TLS)

# set username and password
#client.username_pw_set(user,password=password)

# connect to HiveMQ Cloud on port 8883
client.connect(broker,1883,60)
while True:
    x=input("pesan: ")
    qs=int(input("QOS   : "))
    password = "123"
    if qs <=2 and qs >=0:
        # First let us encrypt secret message
        encrypted = encrypt(x, password)
        print(encrypted)
        encode_data = json.dumps(encrypted, indent=2).encode('utf-8')
        client.publish("mqtt/rafly", payload=encode_data , qos=qs)
        print("Just published message to topic mqtt/rafly")
    else :
        print("QOS out of level")
    time.sleep(1)