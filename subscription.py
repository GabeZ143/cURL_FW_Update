import requests
from requests.auth import HTTPDigestAuth
import os, time
import sys

CAM_IP   = "192.168.99.152"
USER     = "admin"
PWD      = "MIUtrailer123"
SUB_IDX  = "38a8fa50-7161-11f0-9bd7-21d549bcae72"

def start_firmware_upgrade():
    """
    Matches:
    curl -v \
      -X POST 'http://192.168.99.10/onvif/device_service/GetCapabilities' \
      -H 'Content-Type: application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/StartFirmwareUpgrade"' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Connection: Close' \
      --data-binary @body.xml
    """
    # Load the SOAP envelope payload
    with open('body.xml', 'rb') as f:
        xml_body = f.read()

    url = f'http://{CAM_IP}/onvif/device_service/GetCapabilities'
    headers = {
        'Content-Type': (
            'application/soap+xml; charset=utf-8; '
            'action="http://www.onvif.org/ver10/device/wsdl/StartFirmwareUpgrade"'
        ),
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'Close'
    }

    resp = requests.post(url, headers=headers, data=xml_body, timeout=30)
    print('StartFirmwareUpgrade →', resp.status_code, resp.reason)
    print(resp.text)

def upload_firmware():
  """
  Matches:
  curl -v \
        -H 'Authorization: Digest username=\"admin\",realm=\"ONVIF To 34B033\",nonce=\"49bcc52f9982207f384bb73008ab7a37\",uri=\"/onvif/update\",cnonce=\"722047fb2b340212e89d2c69ba98af19\",nc=00000001,qop=\"auth\",response=\"97be8973eeea4e7aa356c74e0337c5dc\",opaque=\"4HTtbO8h\"' \
        -H 'Content-Type: application/octet-stream' \
        --data-binary @firmware.bin \
        http://192.168.99.10/onvif/update
  """
  AUTH_HEADER = (
      'Digest '
      'username="admin",realm="ONVIF To 34B033",'
      'nonce="49bcc52f9982207f384bb73008ab7a37",'
      'uri="/onvif/update",'
      'cnonce="722047fb2b340212e89d2c69ba98af19",'
      'nc=00000001,'
      'qop="auth",'
      'response="97be8973eeea4e7aa356c74e0337c5dc",'
      'opaque="4HTtbO8h"'
  )

  url = f'http://{CAM_IP}/onvif/update'
  headers = {
      'Authorization': AUTH_HEADER,
      'Content-Type': 'application/octet-stream'
  }

  with open('3.6O.bin', 'rb') as fw:
    resp = requests.post(
        url,
        headers=headers,
        data=fw,
        timeout=300
    )

  print('Firmware upload →', resp.status_code, resp.reason)
  print(resp.text)

def Subscribe():
  # Build a minimal <UsernameToken> with PasswordText
  created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
  xml = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
      xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
      <a:Action s:mustUnderstand="1">
        http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest
      </a:Action>
      <a:MessageID>urn:uuid:{os.urandom(16).hex()}</a:MessageID>
      <a:ReplyTo><a:Address>
        http://www.w3.org/2005/08/addressing/anonymous
      </a:Address></a:ReplyTo>
      <Security s:mustUnderstand="1"
        xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <UsernameToken>
          <Username>{USER}</Username>
          <Password 
          Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">
            {PWD}
          </Password>
          <Created 
          xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            {created}
          </Created>
        </UsernameToken>
      </Security>
      <a:To s:mustUnderstand="1">
        http://{CAM_IP}/Subscription?Idx={SUB_IDX}
      </a:To>
    </s:Header>
    <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">
      <Renew xmlns="http://docs.oasis-open.org/wsn/b-2">
        <TerminationTime>PT1M</TerminationTime>
      </Renew>
    </s:Body>
  </s:Envelope>"""

  headers = {
    "Content-Type":
      'application/soap+xml; charset=utf-8;'
      ' action="http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest"',
    "SOAPAction": "http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest",
    "Connection": "Close"
  }

  resp = requests.post(
    f"http://{CAM_IP}/Subscription?Idx={SUB_IDX}",
    headers=headers,
    data=xml.encode("utf-8"),
    auth=HTTPDigestAuth(USER, PWD),
    timeout=10
  )
  print('Subscribe →', resp.status_code, resp.reason)
  print(resp.text)

if __name__ == '__main__':
  start_firmware_upgrade()
  Subscribe()
  Subscribe()
  upload_firmware()

