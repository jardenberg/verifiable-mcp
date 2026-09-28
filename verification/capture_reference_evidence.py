"""Capture public status responses and independently verify their signed bindings."""
import base64
import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request
from urllib.parse import urlsplit
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from check_live import TARGETS

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'verification'/datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
OUT.mkdir(exist_ok=True)
KEY = 'org.jardenberg/verifiable-mcp'
def decode(s): return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
def digest(b): return 'sha256:'+hashlib.sha256(b).hexdigest()
def fetch(url, body=None, headers=None):
    request = urllib.request.Request(url, data=body, headers={'User-Agent':'verifiable-mcp-reference-audit/0.2.2', **(headers or {})})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode()
    if raw.lstrip().startswith('{'):
        return json.loads(raw)
    for event in raw.replace('\r\n', '\n').split('\n\n'):
        data = '\n'.join(line[5:].lstrip(' ') for line in event.splitlines() if line.startswith('data:'))
        if data.strip():
            message = json.loads(data)
            if message.get('id') == 1:
                return message
    raise ValueError(f'No matching response from {url}')
def check(target):
    name, endpoint, tool, protocol = target
    origin = urlsplit(endpoint)
    card_url = f'{origin.scheme}://{origin.netloc}/.well-known/mcp.json'
    card = fetch(card_url)
    msg = fetch(endpoint, json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':tool,'arguments':{}}}).encode(),
        {'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':protocol,'Mcp-Method':'tools/call','Mcp-Name':tool})
    assert msg['id']==1 and 'error' not in msg
    result = msg['result']; assert not result.get('isError')
    env = result['_meta'][KEY]; assert env['spec']=='0.2.1'
    h,p,s = env['jws'].split('.')
    header = json.loads(decode(h)); wrapper = json.loads(decode(p))
    assert header['alg']=='EdDSA' and header['typ']=='verifiable-mcp+jws'
    assert not set(header).intersection({'jwk','jku','x5u','x5c'})
    jwk = next(k for k in card['signing']['jwks']['keys'] if k['kid']==header['kid'])
    thumbprint = base64.urlsafe_b64encode(hashlib.sha256(rfc8785.dumps({k:jwk[k] for k in ('crv','kty','x')})).digest()).rstrip(b'=').decode()
    assert header['kid']==thumbprint
    Ed25519PublicKey.from_public_bytes(decode(jwk['x'])).verify(decode(s),f'{h}.{p}'.encode())
    assert decode(p)==rfc8785.dumps(wrapper)
    assert rfc8785.dumps(wrapper['payload'])==rfc8785.dumps(result['structuredContent'])
    assert wrapper['payload_digest']==digest(rfc8785.dumps(result['structuredContent']))
    assert wrapper['content_digest']==digest(result['content'][0]['text'].encode())
    prov=wrapper['provenance']; fields=[k for k in ('license','legal_basis','rights') if k in prov]; assert len(fields)==1
    assert {'server_operator','dataset_version','last_updated'} <= set(prov)
    assert isinstance(prov.get('canonical_origin'),str) or isinstance(prov.get('publishers'),list)
    file=OUT/f'{name}-public-wire.json'
    file.write_text(json.dumps({'card':card,'response':msg},ensure_ascii=False,indent=2)+'\n')
    return {'name':name,'endpoint':endpoint,'tool':tool,'card_url':card_url,'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'spec_version':env['spec'],'kid':header['kid'],'previous_kids':card['signing'].get('previous_kids',[]),
            'provenance':prov,'response_sha256':digest(rfc8785.dumps(msg)), 'evidence':file.name,'verified':True}
if __name__=='__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool: records=list(pool.map(check,TARGETS))
    (OUT/'independent-bindings.json').write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n')
    for record in records: print(record['name'],record['verified'],record['provenance'])
