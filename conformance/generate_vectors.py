"""Independent, deterministic test vectors. All keys and data are synthetic.

Generate with Python cryptography; production Dart/Rust code is never imported.
"""
import base64, hashlib, json, unicodedata
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64(value): return base64.b64encode(value).decode()
def pattern(size): return bytes((i * 17 + 23) % 251 for i in range(size))
def digest(value): return {'length': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
def evp(secret, salt, encoding='utf-8'):
    material = previous = b''
    while len(material) < 48:
        previous = hashlib.md5(previous + secret.encode(encoding) + salt).digest()
        material += previous
    return material[:32], material[32:48]
def cbc(text, secret, encoding='utf-8'):
    salt = bytes(range(1, 9)); key, iv = evp(secret, salt, encoding)
    raw = text.encode(); padding = 16 - len(raw) % 16
    encrypted = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(raw + bytes([padding]) * padding)
    return (b'Salted__' + salt + encrypted).hex()

def payload(data, identifier):
    if len(data) <= 4096:
        return {'encrypted': b64(data)}
    relative = 'generated/' + identifier + '.bin'
    path = Path(__file__).parent / relative
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(data)
    return {'encrypted_file': relative}

def build():
    cases = []
    def case(identifier, op, expected, **data):
        cases.append(dict(id=identifier, op=op, expected=expected, **data))
    nonce = b'aaaaaaaaaaaa'; key = b'0123456789abcdefghijklmnopqrstuv'
    master = 'conformance-only-master-key'
    texts = ['', 'hello', 'Grüße 中文 🚀', 'line\ncarriage\r\tzero\u0000end']
    for version in [1, 2]:
        for i, password in enumerate(['password', 'pässwörd 中文']):
            salt = 'test-only-salt'
            raw = hashlib.pbkdf2_hmac('sha512', password.encode(), salt.encode(), 200000, 64).hex()
            expected = {'masterKey': raw[:64] if version == 2 else raw,
                        'password': hashlib.sha512(raw[64:].encode()).hexdigest() if version == 2 else raw}
            case(f'filen.login.v{version}.{i}', 'filen.login', expected, password=password, salt=salt, version=version)
    for i, text in enumerate(texts):
        derived = hashlib.pbkdf2_hmac('sha512', master.encode(), master.encode(), 1, 32)
        encrypted = '002' + nonce.decode() + b64(AESGCM(derived).encrypt(nonce, text.encode(), None))
        case(f'filen.metadata.encrypt.{i}', 'filen.metadata.encrypt', encrypted, text=text, key=master)
        case(f'filen.metadata.decrypt.{i}', 'filen.metadata.decrypt', text, encrypted=encrypted, key=master)
    good = cases[-1]['encrypted']
    for name, encrypted, secret in [('wrong-key', good, 'wrong-key'), ('truncated', '002', master),
            ('invalid-base64', '002aaaaaaaaaaaa!!!', master), ('unknown-version', '999'+good[3:], master),
            ('unicode-nonce', '002a'+'é'*11+good[15:], master)]:
        case('filen.metadata.reject.'+name, 'filen.metadata.decrypt', {'status':'rejected'}, encrypted=encrypted, key=secret)
    for size in [0, 1, 15, 16, 17, 65535, 65536, 65537, 1048593]:
        data = pattern(size); encrypted = nonce + AESGCM(key).encrypt(nonce, data, None)
        case(f'filen.chunk.{size}', 'filen.chunk', digest(data), size=size, key=key.hex(),
            export=True, **payload(encrypted, f'filen.chunk.{size}'))
    tiny = nonce + AESGCM(key).encrypt(nonce, b'hello', None)
    for name, encrypted, raw_key in [('empty',b'',key),('short',tiny[:11],key),
            ('missing-tag',tiny[:20],key),('tampered',tiny[:-1]+bytes([tiny[-1]^1]),key),
            ('wrong-key',tiny,b'x'*32),('key-16',tiny,b'x'*16),('key-31',tiny,b'x'*31),('key-33',tiny,b'x'*33)]:
        case('filen.chunk.reject.'+name,'filen.chunk.decrypt',{'status':'rejected'},encrypted=b64(encrypted),key=raw_key.hex())
    # Valid AES-128/192 ciphertext must still be rejected by an AES-256-only
    # API; a wrong-key fixture alone would not detect accidental AES-128 use.
    for length in [16, 24]:
        short_key=b'x'*length
        sealed=nonce+AESGCM(short_key).encrypt(nonce,b'hello',None)
        case(f'filen.chunk.reject.valid-aes-{length*8}','filen.chunk.decrypt',{'status':'rejected'},encrypted=b64(sealed),key=short_key.hex())
    for length in [0, 1, 16, 24, 31, 33]:
        case(f'filen.chunk.encrypt.reject.key-{length}','filen.chunk.encrypt.reject',{'status':'rejected'},key=(b'x'*length).hex())
    for i,password in enumerate(['password','pässwörd 中文','']):
        salt='0102030405060708'
        case(f'internxt.password.{i}','internxt.password',hashlib.pbkdf2_hmac('sha1',password.encode(),bytes.fromhex(salt),10000,32).hex(),password=password,salt=salt)
    for salt in ['x', '123']:
        extra = {}
        if salt == '123':
            expected_hash=hashlib.pbkdf2_hmac('sha1',b'password',bytes.fromhex('0123'),10000,32).hex()
            extra={'known_difference':'Dart pads odd-length hex salts with a leading zero; Rust rejects them',
                   'engine_expected':{'dart':{'status':'ok','value':expected_hash}}}
        case('internxt.password.reject.'+salt,'internxt.password',{'status':'rejected'},password='password',salt=salt,**extra)
    for i,text in enumerate(texts):
        encrypted=cbc(text,'test-only-app-secret')
        case(f'internxt.text.decrypt.{i}','internxt.text.decrypt',text,encrypted=encrypted,key='test-only-app-secret')
        extra = {'known_difference':'Dart PointyCastle cannot encrypt an empty text',
                 'engine_expected':{'dart':{'status':'rejected'}}} if text=='' else {}
        case(f'internxt.text.roundtrip.{i}','internxt.text.roundtrip',text,text=text,key='test-only-app-secret',export=True,**extra)
    magic = bytes.fromhex(cbc('hello','test-only-app-secret'))
    for name,encrypted in [('short','00'),('not-hex','zz'),('invalid-length',magic[:-1].hex()),
            ('bad-magic',(b'Invalid!'+magic[8:]).hex())]:
        extra = {'known_difference':'Dart does not validate the Salted__ header',
                 'engine_expected':{'dart':{'status':'ok','value':'hello'}}} if name=='bad-magic' else {}
        case('internxt.text.reject.'+name,'internxt.text.decrypt',{'status':'rejected'},encrypted=encrypted,key='test-only-app-secret',**extra)
    # A deliberate compatibility diagnostic: the Dart legacy function uses
    # Latin-1 while Rust uses UTF-8. Do not silently pretend these are equivalent.
    for label,encoding in [('utf8','utf-8'),('latin1','latin-1')]:
        case('internxt.text.encoding.'+label,'internxt.text.decrypt','Grüße',encrypted=cbc('Grüße','sécret',encoding),key='sécret',
            known_difference='Legacy text secret encoding differs: Dart Latin-1, Rust UTF-8',
            engine_expected={('dart' if label=='utf8' else 'rust'):{'status':'rejected'}})
    mnemonic='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    bucket=bytes.fromhex('0123456789abcdef01234567')
    seed=hashlib.pbkdf2_hmac('sha512',unicodedata.normalize('NFKD',mnemonic).encode(),b'mnemonic',2048,64)
    for index_id,index in enumerate([bytes(range(32)),b'\xff'*16+bytes(range(16))]):
        bucket_key=hashlib.sha512(seed+bucket).digest()
        file_key=hashlib.sha512(bucket_key[:32]+index).digest()[:32]
        common={'mnemonic':mnemonic,'bucket':bucket.hex(),'index':index.hex()}
        case(f'internxt.key.{index_id}','internxt.key',file_key.hex(),**common)
        for size in [0,1,15,16,17,65535,65536,65537,1048593]:
            data=pattern(size)
            encrypted=Cipher(algorithms.AES(file_key),modes.CTR(index[:16])).encryptor().update(data)
            case(f'internxt.ctr.{index_id}.{size}','internxt.ctr',digest(data),size=size,export=True,**payload(encrypted,f'internxt.ctr.{index_id}.{size}'),**common)
        for offset in [0,16,65536,4294967296]:
            data=pattern(1031); counter=(int.from_bytes(index[:16],'big')+offset//16)%(1<<128)
            encrypted=Cipher(algorithms.AES(file_key),modes.CTR(counter.to_bytes(16,'big'))).encryptor().update(data)
            case(f'internxt.range.{index_id}.{offset}','internxt.range',digest(data),encrypted=b64(encrypted),offset=offset,**common)
        data=pattern(196641)
        sealed=Cipher(algorithms.AES(file_key),modes.CTR(index[:16])).encryptor().update(data)
        case(f'internxt.stream.{index_id}','internxt.stream',digest(data),chunks=[16,65536,32,65520,65537],
             **payload(sealed,f'internxt.stream.{index_id}'),**common)
        for offset in [-16,1,17]:
            extra = {}
            if offset < 0:
                counter=(int.from_bytes(index[:16],'big')-1)%(1<<128)
                decoded=Cipher(algorithms.AES(file_key),modes.CTR(counter.to_bytes(16,'big'))).encryptor().update(b'payload')
                extra={'known_difference':'Dart accepts negative aligned offsets',
                       'engine_expected':{'dart':{'status':'ok','value':digest(decoded)}}}
            case(f'internxt.range.reject.{index_id}.{offset}','internxt.range',{'status':'rejected'},encrypted=b64(b'payload'),offset=offset,**common,
                **extra)
    return {'schema':1,'generator':'Python hashlib + cryptography; fixed synthetic data only','cases':cases}

if __name__=='__main__':
    path=Path(__file__).with_name('vectors.json')
    data = build()
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    print(f'Wrote {len(data["cases"])} independent cases to {path.name}')
