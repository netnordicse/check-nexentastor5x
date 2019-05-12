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
    # Variable declaration
    nexenta_api_url = ''
    nexenta_api_user = ''
    nexenta_api_password = ''
    token = get_token(nexenta_api_url, nexenta_api_user, nexenta_api_password)
    token = token['token']
    headers = {'Authorization': 'Bearer ' + str(token)}

    # Parser
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_alert = subparsers.add_parser('alert',
        help='Query the API for Alerts'
    )
    parser_alert.add_argument("severity",
        help = "Choose which severity to display: minor, major, critical",
    )
    parser_alert.add_argument("faulty",
        help = "If true gather only active issues"
    )
    parser_log = subparsers.add_parser('log',
        help='Query logs from API'
    )
    parser_log.add_argument("severity",
        help = "Choose which severity to display: info, warning, critical"
    )

    if sys.argv[1]:
        stdin = sys.argv[1]

    args_stdin = parser.parse_args()

    if token:
        token_status = get_session_status(headers,
            nexenta_api_url,
            nexenta_api_user
        )
        if token_status == 200:
            if stdin == 'alert':
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
            if stdin == 'log':
                print("Option not avalible yet, only testing")
        else:
            print("Failed to authenticate, got: " + str(token_status))
        logged_out = end_session(headers, nexenta_api_url)

if __name__ == '__main__':
    main()