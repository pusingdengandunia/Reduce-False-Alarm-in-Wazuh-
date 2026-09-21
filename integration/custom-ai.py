import json
import os
import sys

ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'

ALERT_INDEX = 1
WEBHOOK_INDEX = 3

def main(args):
    global debug_enabled
    try:
        if len(args) >= 4:
            msg = '{0} {1} {2} {3}'.format(args[1], args[2], args[3], args[4] if len(args) > 4 else '')
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            with open(LOG_FILE, 'a') as f:
                f.write('# ERROR: Wrong arguments\n')
            sys.exit(ERR_BAD_ARGUMENTS)

        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        process_args(args)

    except Exception as e:
        debug(str(e))
        raise

def process_args(args):
    alert_file_location = args[ALERT_INDEX]
    webhook = args[WEBHOOK_INDEX]

    json_alert = get_json_alert(alert_file_location)
    debug(f'# Alert loaded: {json_alert}')

    send_to_ai(json_alert, webhook)

def debug(msg):
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

def send_to_ai(alert, url):
    headers = {'Content-Type': 'application/json'}
    try:
        res = requests.post(url, json=alert, headers=headers, timeout=10)
        with open(LOG_FILE, 'a') as f:
            f.write(f'# AI response: {res.text}\n')
        debug(f'# AI response: {res.text}')
    except Exception as e:
        with open(LOG_FILE, 'a') as f:
            f.write(f'# AI request failed: {str(e)}\n')

def get_json_alert(file_location):
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)

if __name__ == '__main__':
    main(sys.argv)
