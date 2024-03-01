import os 
import pickle
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

logger = logging.getLogger("messenger")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


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

        self.DHs = generate_dh()

    def generateCertificate(self):
        
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
        logger.debug("##################################################################")
        logger.debug(f"[{self.name}]: Sending message to: [{name}]")
        if name not in self.conns:
            logger.debug(f"[{self.name}]: No connection with {name} yet")
            remote_pub = serialization.load_pem_public_key(self.certs[name]['public_key']) 
            logger.debug(f"[{self.name}]: Using initial pub key for [{name}]")
            pr_k, pu_k = self.DHs
            logger.debug(f"[{self.name}]: Using initial key pair")
            shared_key = dh(pr_k, remote_pub)
            logger.debug(f"[{self.name}]: DH key exchange")
            rk, cks = kdf_rk(shared_key , shared_key)
            logger.debug(f"[{self.name}]: Derive new RK, CKs")
            self.conns[name] = {
                'rk': rk,
                'cks': cks,
                'ckr': None,
                'remote_pub': remote_pub,
                'local_pr': pr_k,
                'local_pub': pu_k,
                'last_to_send': True
            }
            logger.debug(f"[{self.name}]: Last to send")
        elif (self.conns[name]['cks'] is None) or (not self.conns[name]['last_to_send']):
            if self.conns[name]['cks'] is None:
                logger.debug(f"[{self.name}]: Sending for the first time to [{name}]")
            else:
                logger.debug(f"[{self.name}]: Sending after receiving from [{name}]")
            remote_pub = self.conns[name]['remote_pub']
            logger.debug(f"[{self.name}]: Using stored pub key for [{name}]")
            pr_k, pu_k = generate_dh()
            logger.debug(f"[{self.name}]: Generating new key pair")
            shared_key = dh(pr_k, remote_pub)
            logger.debug(f"[{self.name}]: DH key exchange")
            rk, cks = kdf_rk(self.conns[name]['rk'] , shared_key)
            logger.debug(f"[{self.name}]: Deriving new RK, CKs")
            self.conns[name] = {
                'rk': rk,
                'cks': cks,
                'ckr': self.conns[name]['ckr'],
                'remote_pub': remote_pub,
                'local_pr': pr_k,
                'local_pub': pu_k,
                'last_to_send': True
            }
            logger.debug(f"[{self.name}]: Last to send")
            
        session = self.conns[name]
        session['cks'], mk = kdf_ck(session['cks'])
        logger.debug(f"[{self.name}]: Deriving new CKs, MK")
        nonce, ciphertext = encrypt(mk, message)
        logger.debug(f"[{self.name}]: Encrypting message")
        header = {
            'nonce': nonce,
            'public_key': session['local_pub'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        } 
        return header, ciphertext

    def receiveMessage(self, name, header, ciphertext):
        logger.debug("-------------------------------")
        logger.debug(f"[{self.name}]: Received message from: [{name}]")
        if name not in self.conns:
            logger.debug(f"[{self.name}]: No connection with [{name}] yet")
            pr_k, pu_k = self.DHs
            logger.debug(f"[{self.name}]: Using initial key pair")
            remote_pub = serialization.load_pem_public_key(header['public_key'])
            logger.debug(f"[{self.name}]: Using pub key in header for [{name}]")
            shared_key = dh(pr_k, remote_pub)
            logger.debug(f"[{self.name}]: DH key exchange")
            rk, ckr = kdf_rk(shared_key, shared_key)
            logger.debug(f"[{self.name}]: Deriving new RK, CKr")
            self.conns[name] = {
                'rk': rk,
                'cks': None,   
                'ckr': ckr,
                'remote_pub': remote_pub,
                'local_pr': pr_k,
                'local_pub': pu_k,
                'last_to_send': False
            }
            logger.debug(f"[{self.name}]: Not last to send")
        elif self.conns[name]['ckr'] is None:
            logger.debug(f"[{self.name}]: Receiving for the first time from [{name}]")
            pr_k, pu_k = self.conns[name]['local_pr'], self.conns[name]['local_pub']
            logger.debug(f"[{self.name}]: Using last used key pair in sending")
            remote_pub = serialization.load_pem_public_key(header['public_key'])
            logger.debug(f"[{self.name}]: Using pub key from the header of [{name}]")
            shared_key = dh(pr_k, remote_pub)
            logger.debug(f"[{self.name}]: DH key exchange")
            rk, ckr = kdf_rk(self.conns[name]['rk'], shared_key)
            logger.debug(f"[{self.name}]: Deriving new RK, CKr")
            self.conns[name] = {
                'rk': rk,
                'cks': self.conns[name]['cks'],
                'ckr': ckr,
                'remote_pub': remote_pub,
                'local_pr': pr_k,
                'local_pub': pu_k,
                'last_to_send': False
            }
            logger.debug(f"[{self.name}]: Not last to send")

        session = self.conns[name]
        new_remote_pub = serialization.load_pem_public_key(header['public_key'])
        session_pub_key = session['remote_pub'].public_bytes(encoding=serialization.Encoding.PEM, 
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
        if header['public_key'] != session_pub_key:
            logger.debug(f"[{self.name}]: Header of [{name}] changed!")
            pr_k, pu_k = self.conns[name]['local_pr'], self.conns[name]['local_pub']
            logger.debug(f"[{self.name}]: Using last used key pair in sending")
            shared_key = dh(pr_k, new_remote_pub)
            logger.debug(f"[{self.name}]: DH key exchange")
            session['rk'], session['ckr'] = kdf_rk(session['rk'], shared_key)
            logger.debug(f"[{self.name}]: Deriving new RK, CKr")
            session['remote_pub'] = new_remote_pub
            logger.debug(f"[{self.name}]: Updated stored pub key for [{name}]")
            session['local_pr'] = pr_k
            session['local_pub'] = pu_k    
            
        session['last_to_send'] = False      
        session['ckr'], mk = kdf_ck(session['ckr'])
        logger.debug(f"[{self.name}]: Deriving new CKr, MK")
        plaintext = decrypt(mk, header['nonce'], ciphertext)
        logger.debug(f"[{self.name}]: Decrypting message")
        return plaintext.decode('utf-8') if plaintext else None

def generate_dh():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key

def dh(dh_pr, dh_pub):
    return dh_pr.exchange(ec.ECDH(), dh_pub)

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
    except InvalidTag:
        logger.debug("Decryption failed")
        # if e == InvalidTag:
        return None
        # raise

    return plaintext
