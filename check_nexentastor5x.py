import requests
import sys
import json

# Query and return an auth token for this session
def get_token(nexenta_api_url, nexenta_api_user, nexenta_api_password):
    payload = { "username": nexenta_api_user, "password": nexenta_api_password }
    request = requests.post(nexenta_api_url + '/auth/login', data=payload, verify=False)
    return json.loads(request.text)

# Query session status towards the API
def get_session_status(headers, nexenta_api_url, nexenta_api_user):
    payload = { "username": nexenta_api_user }
    request = requests.get(nexenta_api_url + '/auth/status', verify=False, headers=headers)
    return request.status_code

def main():
    # Variable declaration
    nexenta_api_url = ''
    nexenta_api_user = ''
    nexenta_api_password = ''
    token = get_token(nexenta_api_url, nexenta_api_user, nexenta_api_password)
    token = token['token']
    headers = {'Authorization': 'Bearer ' + str(token)}

    if token:
        token_status = get_session_status(headers, nexenta_api_url, nexenta_api_user)
        print(token_status)
        print("Yay, we are authorized")

if __name__ == '__main__':
    main()
