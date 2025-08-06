import requests
from requests.auth import HTTPDigestAuth
import os, time
import sys
import os, time, uuid, xml.etree.ElementTree as ET
import hashlib
from urllib.parse import urlparse
import base64

CAM_IP   = "192.168.99.10"
USER     = "admin"
PWD      = "MIUtrailer123"
BODY_XML   = 'body.xml'       # your StartFirmwareUpgrade envelope
FW_FILE    = '5.0T.bin'   # your firmware blob
UPLOAD_URL = f'http://{CAM_IP}/onvif/update'

NS = {
  'soap': 'http://www.w3.org/2003/05/soap-envelope',
  'tds':  'http://www.onvif.org/ver10/device/wsdl',
  'wsn':  'http://docs.oasis-open.org/wsn/b-2',
  'wsa':  'http://www.w3.org/2005/08/addressing',
  'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
  'wsu':  'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
}

def find_xaddr(tree, parent_tag):
    """
    Walk the parsed XML tree to find a <parent_tag> element
    and return its <XAddr> child text, regardless of namespace.
    """
    for parent in tree.iter():
        # parent.tag may be '{namespace}Device' or 'Device'
        if parent.tag.endswith(parent_tag):
            for child in parent:
                if child.tag.endswith('XAddr'):
                    return child.text
    return None

def get_endpoints():
  """
  Fetch GetCapabilities, parse its XML, and return the
  device, events, and firmware service URLs.
  """
  # Build minimal GetCapabilities envelope (you can load from file too)
  gc_body = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header>
      <Security s:mustUnderstand="1"
        xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <UsernameToken>
          <Username>{USER}</Username>
          <Password Type="http://docs.oasis-open.org/wss/...#PasswordText">
            {PWD}
          </Password>
          <Created xmlns="http://docs.oasis-open.org/wss/...-utility-1.0.xsd">
            {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
          </Created>
        </UsernameToken>
      </Security>
    </s:Header>
    <s:Body>
      <tds:GetCapabilities xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
        <tds:Category>All</tds:Category>
      </tds:GetCapabilities>
    </s:Body>
  </s:Envelope>"""

  headers = {
      'Content-Type': (
          'application/soap+xml; charset=utf-8; '
          'action="http://www.onvif.org/ver10/device/wsdl/GetCapabilities"'
      ),
      'Connection': 'Close'
  }
  url = f"http://{CAM_IP}/onvif/device_service/GetCapabilities"

  resp = requests.post(
      url,
      headers=headers,
      data=gc_body.encode('utf-8'),
      auth=HTTPDigestAuth(USER, PWD),
      timeout=30
  )
  resp.raise_for_status()

  tree = ET.fromstring(resp.text)
  device_svc   = find_xaddr(tree, 'Device')
  events_svc   = find_xaddr(tree, 'Events')
  sys_xaddr    = find_xaddr(tree, 'System')
  firmware_svc = sys_xaddr or f'http://{CAM_IP}/onvif/update'

  if not device_svc or not events_svc:
      print("❗ Could not find expected XAddr elements. Raw response:")
      print(resp.text)

  return device_svc, events_svc, firmware_svc

def make_wsse_digest(username, password):
    raw_nonce = os.urandom(16)
    b64_nonce = base64.b64encode(raw_nonce).decode()
    created   = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sha1 = hashlib.sha1()
    sha1.update(raw_nonce)
    sha1.update(created.encode())
    sha1.update(password.encode())
    pwd_digest = base64.b64encode(sha1.digest()).decode()
    return b64_nonce, created, pwd_digest

def start_firmware_upgrade(device_svc_url):
    # Generate dynamic WS-Security digest
    nonce, created, pwd_digest = make_wsse_digest(USER, PWD)

    # Build SOAP envelope matching original body.xml format
    xml = f'''<s:Envelope xmlns:s="{NS['soap']}">
  <s:Header>
    <Security s:mustUnderstand="1" xmlns="{NS['wsse']}">
      <UsernameToken>
        <Username>{USER}</Username>
        <Password Type="{NS['wsse']}#PasswordDigest">{pwd_digest}</Password>
        <Nonce EncodingType="{NS['wsse']}#Base64Binary">{nonce}</Nonce>
        <Created xmlns="{NS['wsu']}">{created}</Created>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <StartFirmwareUpgrade xmlns="{NS['tds']}"/>
  </s:Body>
</s:Envelope>'''

    headers = {
        'Content-Type': (
            'application/soap+xml; charset=utf-8; '
            f'action="{NS["tds"]}/StartFirmwareUpgrade"'
        ),
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'Close'
    }

    resp = requests.post(
        device_svc_url,
        headers=headers,
        data=xml.encode('utf-8'),
        auth=HTTPDigestAuth(USER, PWD),
        timeout=60
    )

    print(f"[{CAM_IP}] StartFirmwareUpgrade →", resp.status_code, resp.reason)
    print(resp.text)


# def start_firmware_upgrade(device_svc):
#     """Tell the camera to start its firmware upgrade pull."""
#     with open(BODY_XML, 'rb') as f:
#         body = f.read()
#     headers = {
#       'Content-Type': (
#         'application/soap+xml; charset=utf-8; '
#         f'action="{NS["tds"]}/StartFirmwareUpgrade"'
#       ),
#       'Accept-Encoding': 'gzip, deflate',
#       'Connection': 'Close'
#     }
#     url = device_svc  # usually ends in /onvif/device_service/GetCapabilities
#     resp = requests.post(
#       url, headers=headers, data=body,
#       auth=HTTPDigestAuth(USER, PWD),
#       timeout=30
#     )
#     print(f"[{CAM_IP}] StartFirmwareUpgrade →", resp.status_code)
#     print(resp.text)

def get_digest_challenge(url):
    # 1) Ask for the resource *without* auth so we get a 401 + WWW-Authenticate
    r = requests.get(url, timeout=10, allow_redirects=False)
    if r.status_code not in (401, 407) or 'WWW-Authenticate' not in r.headers:
        raise RuntimeError(f"Expected 401 with WWW-Authenticate, got {r.status_code}")
    return r.headers['WWW-Authenticate']

def build_digest_header(challenge, user, pwd, method, url):
    # Parse out the key/value pairs from the challenge
    challenge = challenge[len("Digest "):]
    parts = [p.strip().split("=",1) for p in challenge.split(",")]
    auth = {k:v.strip('"') for k,v in parts}

    realm  = auth['realm']
    nonce  = auth['nonce']
    qop    = auth.get('qop','auth')
    opaque = auth.get('opaque',None)

    # HA1 = MD5(user:realm:pwd)
    ha1 = hashlib.md5(f"{user}:{realm}:{pwd}".encode()).hexdigest()
    # HA2 = MD5(method:uri)
    uri = urlparse(url).path
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

    nc = "00000001"
    cnonce = hashlib.md5(os.urandom(8)).hexdigest()

    # response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()

    # Assemble header
    hdr = (
      f'Digest username="{user}",realm="{realm}",'
      f'nonce="{nonce}",uri="{uri}",'
      f'cnonce="{cnonce}",nc={nc},qop="{qop}",'
      f'response="{resp}"'
    )
    if opaque:
        hdr += f',opaque="{opaque}"'
    return hdr

def upload_firmware():
    # 1) Grab the correct challenge from the upload endpoint
    challenge = get_digest_challenge(UPLOAD_URL)
    print("Challenge:", challenge)

    # 2) Build the Authorization header
    auth_hdr = build_digest_header(challenge, USER, PWD, "POST", UPLOAD_URL)
    print("Built Auth:", auth_hdr)

    # 3) Send the real firmware blob
    fw_size = os.path.getsize(FW_FILE)
    headers = {
        'Authorization': auth_hdr,
        'Content-Type':  'application/octet-stream',
        'Content-Length': str(fw_size)
    }
    with open(FW_FILE, 'rb') as f:
        r = requests.post(UPLOAD_URL, headers=headers, data=f, timeout=300)
    print("Upload returned:", r.status_code, r.reason)
    print(r.text)

def create_subscription(events_svc):
  """Create an ONVIF event subscription; returns the full Subscription URL (with ?Idx=…)."""
  subscribe_xml = f"""<s:Envelope xmlns:s="{NS['soap']}"
                        xmlns:a="{NS['wsa']}"
                        xmlns:wsn="{NS['wsn']}">
    <s:Header>
      <a:Action s:mustUnderstand="1">
        {NS['wsn']}/SubscriptionManager/Subscribe
      </a:Action>
      <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
      <a:ReplyTo><a:Address>
        http://www.w3.org/2005/08/addressing/anonymous
      </a:Address></a:ReplyTo>
      <Security s:mustUnderstand="1"
        xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <UsernameToken>
          <Username>{USER}</Username>
          <Password 
            Type="...#PasswordText">{PWD}</Password>
          <Created xmlns="...-utility-1.0.xsd">
            {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
          </Created>
        </UsernameToken>
      </Security>
      <a:To s:mustUnderstand="1">{events_svc}/Subscription</a:To>
    </s:Header>
    <s:Body>
      <wsn:Subscribe>
        <wsn:ConsumerReference>
          <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </wsn:ConsumerReference>
      </wsn:Subscribe>
    </s:Body>
  </s:Envelope>"""

  headers = {
    'Content-Type': (
      'application/soap+xml; charset=utf-8; '
      f'action="{NS["wsn"]}/SubscriptionManager/Subscribe"'
    ),
    'Connection': 'Close'
  }
  resp = requests.post(
    f"{events_svc}/Subscription",
    headers=headers,
    data=subscribe_xml.encode('utf-8'),
    auth=HTTPDigestAuth(USER, PWD),
    timeout=30
  )
  tree = ET.fromstring(resp.text)
  addr = tree.find('.//wsn:SubscriptionReference/wsa:Address', {**NS,'wsa':NS['wsa']}).text
  print(f"[{CAM_IP}] Created subscription: {addr}")
  return addr

def renew_subscription(sub_url):
  """Send a single RenewRequest to keep the subscription alive."""
  xml = f"""<s:Envelope xmlns:s="{NS['soap']}" xmlns:a="{NS['wsa']}">
    <s:Header>
      <a:Action s:mustUnderstand="1">
        {NS['wsn']}/SubscriptionManager/RenewRequest
      </a:Action>
      <a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>
      <a:ReplyTo><a:Address>
        http://www.w3.org/2005/08/addressing/anonymous
      </a:Address></a:ReplyTo>
      <Security s:mustUnderstand="1"
        xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <UsernameToken>
          <Username>{USER}</Username>
          <Password Type="...#PasswordText">{PWD}</Password>
          <Created xmlns="...-utility-1.0.xsd">
            {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
          </Created>
        </UsernameToken>
      </Security>
      <a:To s:mustUnderstand="1">{sub_url}</a:To>
    </s:Header>
    <s:Body>
      <wsn:Renew xmlns="http://docs.oasis-open.org/wsn/b-2">
        <TerminationTime>PT1M</TerminationTime>
      </wsn:Renew>
    </s:Body>
  </s:Envelope>"""

  headers = {
    'Content-Type': (
      'application/soap+xml; charset=utf-8; '
      f'action="{NS["wsn"]}/SubscriptionManager/RenewRequest"'
    ),
    'Connection': 'Close'
  }
  resp = requests.post(
    sub_url,
    headers=headers,
    data=xml.encode(),
    auth=HTTPDigestAuth(USER, PWD),
    timeout=30
  )
  print(f"[{CAM_IP}] Renew →", resp.status_code)



if __name__ == '__main__':
  dev_svc, evt_svc, fw_svc = get_endpoints()
  print(dev_svc)
  print(evt_svc)
  print(fw_svc)

  start_firmware_upgrade(dev_svc)
  sub_url = create_subscription(evt_svc)
  renew_subscription(sub_url)
  renew_subscription(sub_url)

  upload_firmware()

