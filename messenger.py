import os 
import pickle
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def signCert(self, cert):
        return self.server_signing_key.sign(cert, ec.ECDSA(hashes.SHA256()))

class MessengerClient:
    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}

    def generateCertificate(self):
        self.DHs = generate_dh()

        self.certificate = {
            'name': self.name,
            'public_key': self.DHs[1].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        }
        return pickle.dumps(self.certificate)

    def receiveCertificate(self, certificate, signature):
        try:
            self.server_signing_pk.verify(
                signature,
                certificate,
                ec.ECDSA(hashes.SHA256())
            )
            self.certs[pickle.loads(certificate)['name']] = pickle.loads(certificate)

        except InvalidSignature:
            raise Exception("Invalid signature! The certificate has been tampered with.")

    def sendMessage(self, name, message):
        if name not in self.conns or 'cks' not in self.conns[name]: 
            pr_k, pu_k = generate_dh()
            remote_pub = serialization.load_pem_public_key(self.certs[name]['public_key'])
            shared_key = dh((pr_k, pu_k), self.certs[name]['public_key'])
            rk, cks = kdf_rk(None, shared_key)
            self.conns[name] = {
                'rk': rk,
                'cks': cks,
                'remote_pub': remote_pub,
                'local_pr': pr_k,
                'local_pub': pu_k
            }
        session = self.conns[name]
        session['cks'], mk = kdf_ck(session['cks'])
        # print(mk)
        nonce, ciphertext = encrypt(mk, message)
        header = {
            'nonce': nonce,
            'public_key': session['local_pub'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        } 
        return header, ciphertext

    def receiveMessage(self, name, header, ciphertext):
        print("Receiving message from", name)
        if name not in self.conns:
            pr_k, pu_k = self.DHs
            remote_pub = serialization.load_pem_public_key(header['public_key'])
            shared_key = dh((pr_k, pu_k), header['public_key'])
            rk, ckr = kdf_rk(None, shared_key)
            self.conns[name] = {
                'rk': rk,
                'ckr': ckr,
                'remote_pub': remote_pub,
                'local_pr': pr_k,
                'local_pub': pu_k
            }
        session = self.conns[name]
        new_remote_pub = serialization.load_pem_public_key(header['public_key'])
        session_pub_key = session['remote_pub'].public_bytes(encoding=serialization.Encoding.PEM, 
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
        if header['public_key'] != session_pub_key:
            pr_k, pu_k = generate_dh()
            shared_key = dh((pr_k, pu_k), header['public_key'])
            session['rk'], session['ckr'] = kdf_rk(session['rk'], shared_key)
            session['remote_pub'] = new_remote_pub
            session['local_pr'] = pr_k
            session['local_pub'] = pu_k            
            
        session['ckr'], mk = kdf_ck(session['ckr'])
        plaintext = decrypt(mk, header['nonce'], ciphertext)
        return plaintext.decode('utf-8')

def generate_dh():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key

def dh(dh_pair, dh_pub):
    public_key = serialization.load_pem_public_key(
        dh_pub    
    )

    shared_key = dh_pair[0].exchange(ec.ECDH(), public_key)
    
    return shared_key

def kdf_rk(rk, dh_out):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=None
    )

    key = hkdf.derive(dh_out)

    new_rk = key[:32]
    chain_key = key[32:]

    return new_rk, chain_key

def kdf_ck(ck):
    h = hmac.HMAC(ck, hashes.SHA256())
    h.update(b'message key')
    message_key = h.finalize()

    h = hmac.HMAC(ck, hashes.SHA256())
    h.update(b'chain key')
    new_ck = h.finalize()

    return new_ck, message_key

def encrypt(mk, plaintext):
    aesgcm = AESGCM(mk)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return (nonce, ciphertext)

def decrypt(mk, nonce, ciphertext):
    aesgcm = AESGCM(mk)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print("Decryption failed: ", e)
        raise

    return plaintext
