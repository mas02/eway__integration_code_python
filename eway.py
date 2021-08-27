import os
import sys
import random
import string
import pytz
import json
import traceback
import base64  # import base64 encodool0
from time import sleep
from datetime import datetime, timedelta
from bson import ObjectId
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from eway_sdk import security as views
from common import Common
import constants as CONSTANTS

error_codes = CONSTANTS.eway_error_codes

# Access token from Masters india
def get_access_token():
    
    asp_user_data ={}
    response = {}
    requestData = {}    
    decodeResult = {} 
    asp_user_data['username'] = CONSTANTS.accessTokenInfo['username']
    asp_user_data['password'] = CONSTANTS.accessTokenInfo['password']
    asp_user_data['client_id'] = CONSTANTS.accessTokenInfo['client_id']
    asp_user_data['client_secret'] = CONSTANTS.accessTokenInfo['client_secret']
    asp_user_data['grant_type'] = CONSTANTS.accessTokenInfo['grant_type']
    
    json_data = json.dumps(asp_user_data)
    common_obj = Common()
    # generate 16 digit random key
    asp_app_key = common_obj.get_random_code(16) 
    # encrypt the credential data with 16 digit random key
    credential_data = views.encrypt_with_asp_key(asp_app_key, json_data)
    # encrypt 16 digit random key with the masters india sever.crt file
    encpt_asp_app_key = views.encrypt_with_public_key(asp_app_key, 'gst')             
    requestData['credentials_data'] = credential_data.decode('utf8')
    requestData['app_key'] = encpt_asp_app_key.decode('utf8')            
    url = CONSTANTS.gstr_urls["ACCESS_TOKEN"]

    payload = json.dumps(requestData) 
    result = views.send_request(url, payload, 'POST')
    decodeResult = json.loads(result)
    decodeResult['asp_app_key'] = asp_app_key
    
    return decodeResult


# Authenticate from NIC
def eway_auth_token():
    token = get_access_token()

    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)

    common_obj = Common()
    # Generate 32 character random key
    app_key_data = common_obj.get_random_code(32)
    flat_app_key = base64.b64encode(app_key_data.encode('utf8')).decode()
    
    fields = dict()
    req_data = dict()
    req_data['action'] = 'ACCESSTOKEN'
    req_data['username'] = CONSTANTS.GstinInfo['eway_username']
    req_data['password'] = CONSTANTS.GstinInfo['eway_password']
    req_data['app_key'] = flat_app_key    
    
    request = (base64.b64encode(json.dumps(req_data).encode('utf8'))).decode('utf8')
    
    encrpted_data = views.encrypt_with_public_key(request, 'qa-gst')
   
    fields['Data'] =encrpted_data.decode('utf8') 
    fields['other_parameters'] = encrptedOthrParam.decode('utf8')    
    payload = json.dumps(fields)

    header = dict()    
    header['client-id'] = CONSTANTS.accessTokenInfo['client_id']
    header['Gstin'] = CONSTANTS.GstinInfo['gstin']    

    url = CONSTANTS.gstr_urls['auth_url']    
    result = views.send_request(url, payload, 'POST',header)
    
    if result:        
        decodeResult = json.loads(result)
        response = {}
        if 'status' in decodeResult and decodeResult['status'] == "1":
            if 'expiry' in decodeResult:
                response['expiry'] = decodeResult['expiry']
            else:
                response['expiry'] = 360  
            
            response['authtoken'] = decodeResult['authtoken']
            response['sek'] = decodeResult['sek']
            response['status'] = decodeResult['status']
            response['flat_app_key'] = flat_app_key             
            response['error'] = False
        else:
            if 'status' in decodeResult and decodeResult['status'] == "0":          
                if 'error' in decodeResult and decodeResult['error'] is not None:
                    error = base64.b64decode(decodeResult['error']).decode('utf8')
                    error = json.loads(error)
                    response['meaasge'] = error_codes[error['errorCodes']]
                    response['status'] = decodeResult['status'] 
                    response['error'] = True              
                
    else:
        msg = 'Service unavailable. Please try again later'
        response['error'] = True
        response['message'] = msg


    # return response
    print("response===>",response)
    exit()

def generate_eway():    
    
    token = get_access_token()
    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)

    # ewaybill_auth_token = eway_auth_token()
    # flat_app_key = ewaybill_auth_token['flat_app_key']    
    # 32 random character(base64 encode) which is used in auth token API
    flat_app_key = 'YjNJSlozeFd1VFlGWU5Sb2MwVWtnWGtZdnExTVBOWTg='

    # auth token received in auth token API  
    # auth_token = ewaybill_auth_token['authtoken']
    auth_token = 'hEVKJ0Z6zeKNbuwfmfGLJ4CV3'

    # Sek received in auth token API     
    # sek = ewaybill_auth_token['sek']     
    sek = 'eqbwqHCb39fPqBAGNUAGdxgi59yLdJl0+cq0Yyj7HAPQZxPgZOGoXmgmPSrhLGoX'
    
    ek = base64.b64encode(views.decrypt_data(sek, flat_app_key, 'byte')).decode('utf8')
    data_json =  CONSTANTS.data_json
    
    data = views.encrypt_data(data_json, ek, type = 'str')
    
    encrpted_data = data.decode('utf8')
    
    fields={}
    fields['data'] =encrpted_data
    fields['action'] = 'GENEWAYBILL'
    fields['other_parameters'] = encrptedOthrParam.decode('utf8')
    
    payload = json.dumps(fields)
    url = CONSTANTS.gstr_urls['eway_url']
    header = {}
    header['AuthToken']= auth_token
    header['user_name']= CONSTANTS.GstinInfo['eway_username']
    header['Gstin']= CONSTANTS.GstinInfo['gstin']
    header['client-id']=CONSTANTS.accessTokenInfo['client_id']
    method = 'POST' 
    result= views.send_request(url, payload, method, header)
    
    if result:
        response={}
        decodeResult = json.loads(result)
        
        if 'status' in decodeResult and decodeResult['status'] == "1":
            data = views.decrypt_data(decodeResult['data'], ek)
            response['data'] = data.decode('utf8')
            response['error'] = False
            
        else:  
            if 'status' in decodeResult and decodeResult['status'] == "0":          
                if 'error' in decodeResult and decodeResult['error'] is not None:
                    error = base64.b64decode(decodeResult['error']).decode('utf8')
                    error = json.loads(error)
                    response['meaasge'] = error_codes[error['errorCodes']]
                    response['status'] = decodeResult['status'] 
                    response['error'] = True              
            
    else:
        msg = 'Service unavailable. Please try again later'
        response['error'] = True
        response['message'] = msg

    print("response===>",response)
    exit()
    return response

def cancel_eway():    
    
    token = get_access_token()
    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)

    #ewaybill_auth_token = eway_auth_token()
    # flat_app_key = ewaybill_auth_token['flat_app_key']    
    # 32 random character(base64 encode) which is used in auth token API
    flat_app_key = 'QjZxRTJqbTU2U29hOGg3ZDhMSFk4NmR2dnFVZlhOSmk='

    # auth token received in auth token API  
    # auth_token = ewaybill_auth_token['AuthToken']
    auth_token = 'hEVKJ0Z6zeKNbuwfmfGLJ4CV3'

    # Sek received in auth token API     
    # sek = ewaybill_auth_token['Sek']     
    sek = 'T0QFxIuhyEs42r77csWgw9PvNOQut1d+or1GjVTMUIp7fYZSz/8OtGYOUmFnMOB8'
    
    ek = base64.b64encode(views.decrypt_data(sek, flat_app_key, 'byte')).decode('utf8')
    data_json =  CONSTANTS.cancel_eway_json
    
    data = views.encrypt_data(data_json, ek, type = 'str')
    
    encrpted_data = data.decode('utf8')
    
    fields={}
    fields['Data'] =encrpted_data
    fields['action'] ='CANEWB'    
    fields['other_parameters'] = encrptedOthrParam.decode('utf8')
    
    payload = json.dumps(fields)
    url = CONSTANTS.gstr_urls['eway_url']
    header = {}
    header['AuthToken']= auth_token
    header['Gstin']= CONSTANTS.GstinInfo['gstin']
    header['client-id']=CONSTANTS.accessTokenInfo['client_id']
    method = 'POST'
    result= views.send_request(url, payload, method, header)
    
    if result:
        response={}
        decodeResult = json.loads(result)
        if 'status' in decodeResult and decodeResult['status'] == "1":
            data = views.decrypt_data(decodeResult['data'], ek)
            response['data'] = data.decode('utf8')
            response['error'] = False
            
        else:  
            if 'status' in decodeResult and decodeResult['status'] == "0":          
                if 'error' in decodeResult and decodeResult['error'] is not None:
                    error = base64.b64decode(decodeResult['error']).decode('utf8')
                    error = json.loads(error)
                    response['meaasge'] = error_codes[error['errorCodes']]
                    response['status'] = decodeResult['status'] 
                    response['error'] = True          
            
    else:
        msg = 'Service unavailable. Please try again later'
        response['error'] = True
        response['message'] = msg

    print("cancel response===>",response)
    exit()
    return response


def get_eway():

    token = get_access_token()
    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)

    #ewaybill_auth_token = eway_auth_token()
    # flat_app_key = ewaybill_auth_token['flat_app_key']    
    # 32 random character(base64 encode) which is used in auth token API
    flat_app_key = 'QjZxRTJqbTU2U29hOGg3ZDhMSFk4NmR2dnFVZlhOSmk='

    # auth token received in auth token API  
    # auth_token = ewaybill_auth_token['AuthToken']
    auth_token = 'hEVKJ0Z6zeKNbuwfmfGLJ4CV3'

    # Sek received in auth token API     
    # sek = ewaybill_auth_token['Sek']     
    sek = 'T0QFxIuhyEs42r77csWgw9PvNOQut1d+or1GjVTMUIp7fYZSz/8OtGYOUmFnMOB8'

    
    ek = base64.b64encode(views.decrypt_data(sek, flat_app_key, 'byte')).decode('utf8')

    eway_no ="391002703919"
    
    
    url = CONSTANTS.gstr_urls['get_eway']
    url = url+'?ewbNo='+eway_no+'&other_parameters='+encrptedOthrParam.decode('utf8')
    header = {}
    header['AuthToken']= auth_token
    header['Gstin']= CONSTANTS.GstinInfo['gstin']
    header['client-id']=CONSTANTS.accessTokenInfo['client_id']
    
    result= views.send_request(url, '', '', header) 
    
    if result:
        response={}
        decodeResult = json.loads(result)
        if 'status' in decodeResult and decodeResult['status'] == "1":
            key = views.decrypt_data(decodeResult['rek'], ek, 'byte')
            #decrypt Data from key
            encodedData = views.decrypt_data(decodeResult['data'], key)

            if encodedData and encodedData is not None:

                response['data'] = encodedData.decode('utf8')
                response['error'] = False
            
        elif 'status' in decodeResult and decodeResult['status'] == "0":          
            if 'error' in decodeResult and decodeResult['error'] is not None:
                error = base64.b64decode(decodeResult['error']).decode('utf8')
                error = json.loads(error)
                response['meaasge'] = error_codes[error['errorCodes']]
                response['status'] = decodeResult['status'] 
                response['error'] = True

        elif 'Message' in decodeResult:
            response['meaasge'] = decodeResult['Message']
            response['error'] = True
        
        else:
            response['data'] = decodeResult
            response['error'] = True

            
    else:
        msg = 'Service unavailable. Please try again later'
        response['error'] = True
        response['message'] = msg

    print("Get IRN response===>",response)
    exit()
    return response



if __name__ == "__main__":
    # get_access_token()
    eway_auth_token()
    # generate_eway()
    # cancel_eway()
    # get_eway()
