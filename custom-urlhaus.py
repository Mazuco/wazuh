#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars

debug_enabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    debug("# Starting")

    # Read args
    alert_file_location = args[1]

    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)

    # Request urlhaus info
    msg = request_urlhaus_info(json_alert)

    # If positive match, send event to Wazuh Manager
    if msg:
        send_event(msg, json_alert["agent"])

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)

        print(msg)

        f = open(log_file,"a")
        f.write(msg)
        f.close()

def collect(data):
  urlhaus_reference = data['urlhaus_reference']
  url_status = data['url_status']
  url_date_added = data['date_added']
  url_threat = data['threat']
  url_blacklist_spamhaus = data['blacklists']['spamhaus_dbl']
  url_blacklist_surbl = data['blacklists']['surbl']
  url_tags = data['tags']
  return urlhaus_reference, url_status, url_date_added, url_threat, url_blacklist_spamhaus, url_blacklist_surbl, url_tags

def in_database(data, url):
  result = data['query_status']
  debug(result)
  if result == "ok":
    return True
  return False

def query_api(url):
  params = {'url': url}
  response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', params)
  json_response = response.json()
  if json_response['query_status'] == 'ok':
      data = json_response
      debug(data)
      return data
  else:
      alert_output = {}
      alert_output["urlhaus"] = {}
      alert_output["integration"] = "custom-urlhaus"
      json_response = response.json()
      debug("# Error: The URLHAUS integration encountered an error")
      alert_output["urlhaus"]["error"] = response.status_code
      alert_output["urlhaus"]["description"] = json_response["errors"][0]["detail"]
      send_event(alert_output)
      exit(0)

def request_urlhaus_info(alert):
    alert_output = {}
    # If there is no url address present in the alert. Exit.
    if alert["data"]["http"]["redirect"] == None:
      return(0)

    # Request info using urlhaus API
    data = query_api(alert["data"]["http"]["redirect"])

    # Create alert
    alert_output["urlhaus"] = {}
    alert_output["integration"] = "custom-urlhaus"
    alert_output["urlhaus"]["found"] = 0
    alert_output["urlhaus"]["source"] = {}
    alert_output["urlhaus"]["source"]["alert_id"] = alert["id"]
    alert_output["urlhaus"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["urlhaus"]["source"]["description"] = alert["rule"]["description"]
    alert_output["urlhaus"]["source"]["url"] = alert["data"]["http"]["redirect"]
    url = alert["data"]["http"]["redirect"]
    # Check if urlhaus has any info about the url
    if in_database(data, url):
      alert_output["urlhaus"]["found"] = 1

    # Info about the url found in urlhaus
    if alert_output["urlhaus"]["found"] == 1:
        urlhaus_reference, url_status, url_date_added, url_threat, url_blacklist_spamhaus, url_blacklist_surbl, url_tags = collect(data)

        # Populate JSON Output object with urlhaus request
        alert_output["urlhaus"]["urlhaus_reference"] = urlhaus_reference
        alert_output["urlhaus"]["url_status"] = url_status
        alert_output["urlhaus"]["url_date_added"] = url_date_added
        alert_output["urlhaus"]["url_threat"] = url_threat
        alert_output["urlhaus"]["url_blacklist_spamhaus"] = url_blacklist_spamhaus
        alert_output["urlhaus"]["url_blacklist_surbl"] = url_blacklist_surbl
        alert_output["urlhaus"]["url_tags"] = url_tags


    debug(alert_output)

    return(alert_output)

def send_event(msg, agent = None):
    if not agent or agent["id"] == "000":
        string = '1:urlhaus:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->urlhaus:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))

    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(now, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(msg +'\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
