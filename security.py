# from django.shortcuts import render
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import binascii #import string to hex, hex to format
import base64 # import base64 encode and decode 
import json
import time
import requests, pytz, hashlib, hmac
from datetime import datetime
from bson import ObjectId

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5

from common import Common
import core.mongoQuery as MongoQuery
import constants as CONSTANTS
import random
import string


def encrypt_with_public_key(app_key, keyType):
    """
    func used to encrypt the data with public key
    """
    if(keyType == 'gst'):
        # pubKeyFilePath = 'prod_certs/server.crt'
        cert_path = CONSTANTS.gstr_urls["CERIFICATE_PATH"]
        # cert_path = "stage_public_keys/gst/GSTN_PublicKey.pem"
        # pubKeyFilePath = os.path.abspath(cert_path)                        
        root_dir = os.path.dirname(os.path.abspath(__file__))        
        pubKeyFilePath = os.path.join(root_dir, cert_path)
        public_file = open(pubKeyFilePath,'rb')
        key_data = RSA.import_key(public_file.read())     
        cipher_rsa = PKCS1_v1_5.new(key_data)        
        encryptedAppKey = base64.b64encode(cipher_rsa.encrypt(app_key.encode('utf8')))
    elif (keyType == 'qa-gst'):
        # pubKeyFilePath = 'prod_certs/server.crt'
        # cert_path = CONSTANTS.gstr_urls["CERIFICATE_PATH"]
        cert_path = "stage_public_keys/eway/Eway_publickey.pem"  
              
        # pubKeyFilePath = os.path.abspath(cert_path)
        root_dir = os.path.dirname(os.path.abspath(__file__))
        pubKeyFilePath = os.path.join(root_dir, cert_path)        
        public_file = open(pubKeyFilePath, 'rb')
        key_data = RSA.import_key(public_file.read())
        cipher_rsa = PKCS1_v1_5.new(key_data)
        encryptedAppKey = base64.b64encode(cipher_rsa.encrypt(app_key.encode('utf8')))

    return encryptedAppKey


def encrypt_with_asp_key(asp_app_key,json_data):
    """
    func encrypts the data from Master India app_key
    """
    iv =  asp_app_key
    cipher = AES.new(asp_app_key.encode("utf8"), AES.MODE_CBC, iv.encode("utf8"))
    data = pad_data_pkcs5(json_data)
    encrypted_data = binascii.b2a_hex(cipher.encrypt(data.encode("utf8")))

    return encrypted_data

def pad_data_pkcs5(plain_data):
    """
    func to pad cleartext to be multiples of 8-byte blocks.    
    """
    block_size = AES.block_size    
    return plain_data + (block_size - len(plain_data) % block_size) * chr(block_size - len(plain_data) % block_size)

def unpad_data(data):
    return data[:-ord(data[len(data) - 1:])]

def encrypt_data(data, key, type = None):
    if type == "str":
        cipher = AES.new(base64.b64decode(key), AES.MODE_ECB)
    elif(type != None):
        cipher = AES.new(key, AES.MODE_ECB)
    else:  
        cipher = AES.new(key.encode("utf8"), AES.MODE_ECB)

    paddedData = pad_data_pkcs5(data)
    encrypted_data = base64.b64encode(cipher.encrypt(paddedData.encode("utf8")))
    return encrypted_data

def decrypt_data(data, key, type = None):  
    try:        
        key = base64.b64decode(key.encode('utf8'))
        # key.decode()
        # key = key.decode().encode('utf8')
        
        # key = key.encode('utf8')
    except Exception as ex: 
        print(ex)
        key = key
            
    data = base64.b64decode(data)
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_txt = cipher.decrypt(data)
    if type == 'byte':
        return unpad_data(cipher_txt)
    else:
        return unpad_data(cipher_txt) #.decode('utf8')
        # return base64.b64decode(unpad_data(cipher_txt))




def send_request(url, payload = None, method = None, header = None):
    """
    func used to send curl request
    """
    headers = {'content-type': 'application/json'}
    
    if(header != None):
        headers.update(header)
    try:
        if(method == "POST"):
            response = requests.post(url, data=payload, headers=headers)
        elif(method == "PUT"):
            response = requests.put(url, data=payload, headers=headers)
        else:
            response = requests.get(url,headers = headers)    
    
        return response.text
    except Exception as ex:        
        errorRes = {'message': str(ex)}
        return  json.dumps(errorRes)





