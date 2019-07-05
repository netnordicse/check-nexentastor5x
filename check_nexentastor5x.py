import requests
import sys
import json
import argparse
import urllib3

# Disable ssl warning
urllib3.disable_warnings()

# Query and return an auth token for this session
def get_token(nexenta_api_url, nexenta_api_user, nexenta_api_password):
    payload = {
        "username": nexenta_api_user,
        "password": nexenta_api_password
    }
    request = requests.post(
        nexenta_api_url + '/auth/login',
        data=payload,
        verify=False
    )
    return json.loads(request.text)

# Query session status towards the API
def get_session_status(headers, nexenta_api_url, nexenta_api_user):
    payload = {
        "username": nexenta_api_user
    }
    request = requests.get(
        nexenta_api_url + '/auth/status',
        verify=False,
        headers=headers
    )
    return request.status_code

# Ends current API session
def end_session(headers, nexenta_api_url):
    request = requests.post(
        nexenta_api_url + '/auth/logout',
        verify=False,
        headers=headers
    )
    return request.status_code

# Query current alerts
def get_alert_cases(headers, nexenta_api_url, severity, faulty):
    
    severity = str(severity)
    faulty = bool(faulty)

    payload = json.dumps(
        {
            "faulty": faulty,
            "severity": severity
        }
    )
    request = requests.get(nexenta_api_url + '/alert/cases',
        verify=False,
        headers=headers,
        data=payload
    )
    request_json = json.loads(request.text)

    counter = 0
    for entry in request_json['data']:
        if (entry['faulty'] == bool(faulty)) and (entry['severity'] == str(severity)):
            counter += 1
    
    msg = 'There exists: ' + str(counter) + ' ' + str(faulty) + ' ' + str(severity) + ' alerts!'

    if counter > 0:
        if severity == 'minor':
            print('WARNING')
            sys.exit(1)
        elif (severity == 'major') or (severity == 'critical'):
            print('CRITICAL')
            sys.exit(2)
        else:
            print('UNKNOWN')
            sys.exit(3)
    else:
        print('OK')
        sys.exit(0)

def main():
    # Parser
    parser = argparse.ArgumentParser()

    parser.add_argument('-H', '--host',
        type=str, default='127.0.0.1', help='NexentaStor IP / Hostname')
    parser.add_argument('-P', '--port',
        type=int, default=8443, help='NexentaStor REST API port')
    parser.add_argument('-u', '--user',
        type=str, default='api', help='NexentaStor REST API user')
    parser.add_argument('-p', '--password',
        type=str, help='NexentaStor REST API USER password')
    parser.add_argument('-c', '--check',
        type=str, choices=['alert', 'log'], help='Check alert or log')
    parser.add_argument('-s', '--severity',
        type=str, choices=['minor', 'major', 'critical'], help='Choose severity on alerts')
    parser.add_argument('-f', '--faulty',
        type=str, choices=['true', 'false'], help='Show faulty alerts or not')

    args_stdin = parser.parse_args()

    nexenta_api_host = args_stdin.host
    nexenta_api_port = args_stdin.port
    nexenta_api_user = args_stdin.user
    nexenta_api_password = args_stdin.password
    check = args_stdin.check
    severity = args_stdin.severity
    faulty = args_stdin.faulty

    nexenta_api_url = 'https://' + nexenta_api_host + ':' + str(nexenta_api_port)

    token = get_token(nexenta_api_url, nexenta_api_user, nexenta_api_password)
    token = token['token']
    headers = {'Authorization': 'Bearer ' + str(token)}

    if token:
        token_status = get_session_status(headers,
            nexenta_api_url,
            nexenta_api_user
        )
        if token_status == 200:
            if check == 'alert':
                severity = args_stdin.severity
                faulty = args_stdin.faulty
                if (severity) and (faulty):
                    results = get_alert_cases(headers,
                        nexenta_api_url,
                        severity,
                        faulty,
                    )
                    print(results)
                else:
                    print("Failed, either "\
                        + str(severity) + "or"\
                        + str(faulty) + "not defined"
                    )
            if check == 'log':
                print("Option not avalible yet, only testing")
        else:
            print("Failed to authenticate, got: " + str(token_status))
        logged_out = end_session(headers, nexenta_api_url)

if __name__ == '__main__':
    main()
