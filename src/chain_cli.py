#!/root/ext/chain-venv/bin/python
"""Dolvero trust ledger, on-chain anchors (31 Oct 2026).

  chain_cli.py attest '{"payload_sha":"<hex>","leaf_hash":"<hex>","kind":"review","ref":"<rid>","ts":<unix>}'
      -> {"uid": "...", "tx": "..."}      EAS attestation on Base (schema registered on first use)
  chain_cli.py arweave <file.json>            -> {"id": "..."}   permanent upload, tags App-Name/Content-Type
  chain_cli.py arstatus <txid>                -> {"status": 200|202|404}
  chain_cli.py status                         -> balances

Keys: /etc/dolvero/chain/base_signer.json, /etc/dolvero/chain/arweave_wallet.json (root only, backed up on the hub).
"""
import json, sys, os, time
from web3 import Web3
from eth_abi import encode

RPC = os.environ.get('BASE_RPC', 'https://mainnet.base.org')
EAS = Web3.to_checksum_address('0x4200000000000000000000000000000000000021')
REGISTRY = Web3.to_checksum_address('0x4200000000000000000000000000000000000020')
SCHEMA = 'bytes32 payloadSha,bytes32 leafHash,string kind,string ref,uint64 ts'
SIGNER = '/etc/dolvero/chain/base_signer.json'
ARWALLET = '/etc/dolvero/chain/arweave_wallet.json'

EAS_ABI = json.loads('[{"inputs":[{"components":[{"internalType":"bytes32","name":"schema","type":"bytes32"},{"components":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint64","name":"expirationTime","type":"uint64"},{"internalType":"bool","name":"revocable","type":"bool"},{"internalType":"bytes32","name":"refUID","type":"bytes32"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"uint256","name":"value","type":"uint256"}],"internalType":"struct AttestationRequestData","name":"data","type":"tuple"}],"internalType":"struct AttestationRequest","name":"request","type":"tuple"}],"name":"attest","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"payable","type":"function"}]')
REG_ABI = json.loads('[{"inputs":[{"internalType":"string","name":"schema","type":"string"},{"internalType":"address","name":"resolver","type":"address"},{"internalType":"bool","name":"revocable","type":"bool"}],"name":"register","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"uid","type":"bytes32"}],"name":"getSchema","outputs":[{"components":[{"internalType":"bytes32","name":"uid","type":"bytes32"},{"internalType":"address","name":"resolver","type":"address"},{"internalType":"bool","name":"revocable","type":"bool"},{"internalType":"string","name":"schema","type":"string"}],"internalType":"struct SchemaRecord","name":"","type":"tuple"}],"stateMutability":"view","type":"function"}]')
ZERO = '0x0000000000000000000000000000000000000000'

def w3c():
    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={'timeout': 30}))
    k = json.load(open(SIGNER))
    return w3, k['address'], k['private_key']

def send(w3, addr, key, fn):
    tx = fn.build_transaction({'from': addr, 'nonce': w3.eth.get_transaction_count(addr), 'chainId': 8453})
    signed = w3.eth.account.sign_transaction(tx, key)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    rc = w3.eth.wait_for_transaction_receipt(h, timeout=180)
    if rc.status != 1:
        raise SystemExit(json.dumps({'error': 'tx reverted', 'tx': h.hex()}))
    return h.hex(), rc

def schema_uid(w3):
    uid = Web3.solidity_keccak(['string', 'address', 'bool'], [SCHEMA, ZERO, False])
    reg = w3.eth.contract(address=REGISTRY, abi=REG_ABI)
    rec = reg.functions.getSchema(uid).call()
    return uid, rec[0] != b'\x00' * 32

def ensure_schema(w3, addr, key):
    uid, ok = schema_uid(w3)
    if not ok:
        reg = w3.eth.contract(address=REGISTRY, abi=REG_ABI)
        send(w3, addr, key, reg.functions.register(SCHEMA, ZERO, False))
    return uid

def attest(arg):
    a = json.loads(arg)
    w3, addr, key = w3c()
    uid = ensure_schema(w3, addr, key)
    data = encode(['bytes32', 'bytes32', 'string', 'string', 'uint64'],
                  [bytes.fromhex(a['payload_sha']), bytes.fromhex(a['leaf_hash']), a['kind'], str(a['ref']), int(a['ts'])])
    eas = w3.eth.contract(address=EAS, abi=EAS_ABI)
    req = (uid, (ZERO, 0, False, b'\x00' * 32, data, 0))
    h, rc = send(w3, addr, key, eas.functions.attest(req))
    topic = Web3.keccak(text='Attested(address,address,bytes32,bytes32)')
    att = None
    for lg in rc.logs:
        if lg.topics and lg.topics[0] == topic:
            att = '0x' + lg.data.hex()[-64:] if isinstance(lg.data, (bytes, bytearray)) else '0x' + lg.data[-64:]
    print(json.dumps({'uid': att, 'tx': h, 'schema': uid.hex(), 'block': rc.blockNumber}))

def arweave_upload(path):
    from arweave import Wallet, Transaction
    wallet = Wallet(ARWALLET)
    data = open(path, 'rb').read()
    tx = Transaction(wallet, data=data)
    tx.add_tag('Content-Type', 'application/json')
    tx.add_tag('App-Name', 'Dolvero-Trust')
    tx.add_tag('App-Version', '1')
    tx.sign()
    tx.send()
    print(json.dumps({'id': tx.id, 'bytes': len(data), 'reward_winston': str(tx.reward)}))

def arstatus(txid):
    import urllib.request
    try:
        r = urllib.request.urlopen('https://arweave.net/tx/' + txid + '/status', timeout=20)
        body = r.read().decode()
        print(json.dumps({'status': r.status, 'body': body[:200]}))
    except Exception as e:
        code = getattr(e, 'code', 0)
        print(json.dumps({'status': code, 'error': str(e)[:120]}))

def status():
    w3, addr, key = w3c()
    bal = w3.eth.get_balance(addr) / 1e18
    uid, ok = schema_uid(w3)
    import urllib.request
    ar = urllib.request.urlopen('https://arweave.net/wallet/' + json.load(open('/etc/dolvero/chain/ar_address.json'))['address'] + '/balance', timeout=20).read().decode() if os.path.exists('/etc/dolvero/chain/ar_address.json') else 'n/a'
    print(json.dumps({'base_address': addr, 'base_eth': bal, 'schema': uid.hex(), 'schema_registered': ok, 'ar_winston': ar}))

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'attest': attest(sys.argv[2])
    elif cmd == 'arweave': arweave_upload(sys.argv[2])
    elif cmd == 'arstatus': arstatus(sys.argv[2])
    elif cmd == 'status': status()
    else: print(__doc__)
