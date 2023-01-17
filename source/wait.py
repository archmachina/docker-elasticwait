
import os
import requests
import time
import urllib3

def debug_request_result(result):
  print('Request Result: %s' % result.text)
  print('Request Status Code: %s' % result.status_code)

def main():

  # Enable/Disable certificate validation
  cert_verify = True
  temp = os.environ.get('CERT_VERIFY')
  if temp is not None and temp != '':
    urllib3.disable_warnings()
    cert_verify = bool(int(temp))

  # Elastic Environment Vars
  # The elastic host, username and password are mandatory. Port defaults to 9200

  # ELASTIC_HOST
  elastic_host = os.environ.get('ELASTIC_HOST')
  if elastic_host is None or elastic_host == '':
    raise Exception('Missing ELASTIC_HOST')

  # ELASTIC_SCHEME
  elastic_scheme = "https"
  temp = os.environ.get('ELASTIC_SCHEME')
  if temp is not None and temp != '':
    elastic_scheme = temp

  # ELASTIC_PORT
  elastic_port = 9200
  temp = os.environ.get('ELASTIC_PORT')
  if temp is not None and temp != '':
    elastic_port = int(temp)

  # ELASTIC_USERNAME
  elastic_username = os.environ.get('ELASTIC_USERNAME')
  if elastic_username is None or elastic_username == '':
    raise Exception('Missing ELASTIC_USERNAME')

  # ELASTIC_PASSWORD
  elastic_password = os.environ.get('ELASTIC_PASSWORD')
  if elastic_password is None or elastic_password == '':
    raise Exception('Missing ELASTIC_PASSWORD')

  # Elastic authentication
  elastic_check_uri = '%s://%s:%s/_cat/health?format=json' % (elastic_scheme, elastic_host, elastic_port)
  elastic_session = requests.Session()
  elastic_session.auth = (elastic_username, elastic_password)
  elastic_session.verify = cert_verify
  elastic_session.headers = {
    "Content-Type": "application/json"
  }

  # Kibana environment vars
  # Environment vars for kibana are not mandatory, unless the host is specified. If the host is
  # specified, username and password are mandatory.

  check_kibana = False

  # KIBANA_HOST
  kibana_host = os.environ.get('KIBANA_HOST')
  if kibana_host is not None and kibana_host != '':
    check_kibana = True

    # KIBANA_SCHEME
    kibana_scheme = "https"
    temp = os.environ.get('KIBANA_SCHEME')
    if temp is not None and temp != '':
      kibana_scheme = temp

    # KIBANA_PORT
    kibana_port = 5601
    temp = os.environ.get('KIBANA_PORT')
    if temp is not None and temp != '':
        kibana_port = int(temp)

    # KIBANA_USERNAME
    kibana_username = os.environ.get('KIBANA_USERNAME')
    if kibana_username is None or kibana_username == '':
        raise Exception('Missing KIBANA_USERNAME')

    # KIBANA_PASSWORD
    kibana_password = os.environ.get('KIBANA_PASSWORD')
    if kibana_password is None or kibana_password == '':
        raise Exception('Missing KIBANA_PASSWORD')

    # kibana requests setup
    kibana_check_uri = '%s://%s:%s/api/features' % (kibana_scheme, kibana_host, kibana_port)
    kibana_session = requests.Session()
    kibana_session.auth = (kibana_username, kibana_password)
    kibana_session.verify = cert_verify
    kibana_session.headers = {
        "Content-Type": "application/json"
    }

  # General environment vars
  max_attempts = 30
  temp = os.environ.get('MAX_ATTEMPTS')
  if temp is not None and temp != '':
    max_attempts = int(temp)

  wait_time = 30
  temp = os.environ.get('WAIT_TIME')
  if temp is not None and temp != '':
    wait_time = int(temp)

  wait_healthy = True
  temp = os.environ.get('WAIT_HEALTHY')
  if temp is not None and temp != '':
    wait_time = bool(int(temp))

  attempt = 1
  while True:
    # Attempt to connect to the elastic environment
    print('Elastic connection attempt: %s' % attempt)
    try:
      # Attempt to connect to elastic
      print('Checking elastic connectivity: %s' % elastic_check_uri)
      elastic_result = elastic_session.get(elastic_check_uri)
      debug_request_result(elastic_result)
      elastic_result.raise_for_status()

      # Make sure we have a healthy cluster, if requested
      if wait_healthy and elastic_result.json()[0]['status'] != 'green':
        # Good HTTP status, but cluster status is not green
        raise Exception('Could connect to elastic, but cluster status not green')

      # Check for kibana connectivity, if requested
      if check_kibana:
        print('Checking kibana connectivity: %s' % kibana_check_uri)
        kibana_result = elastic_session.get(kibana_check_uri)
        debug_request_result(kibana_result)
        kibana_result.raise_for_status()

      # No errors, so we have connected successfully
      print('Connections were successful. Exiting.')
      return
    except Exception as e:
      print('Could not connect to elastic: %s' % e)

    # Break here if we have tried too many times
    attempt = attempt + 1
    if max_attempts > 0 and attempt > max_attempts:
      raise Exception('Could not connect to elastic and exhausted attempts')

    # Wait before trying again
    print('Sleeping...')
    time.sleep(wait_time)

if __name__ == "__main__":
  main()
