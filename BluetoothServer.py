import socket,json,base64,os
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import padding

class BluetoothServer:
    def _init_(self,host='localhost',port=12345):
        self.host=host
        self.port=port
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.bind((self.host,self.port))
        self.socket.listen(1)
        self.private_key=ec.generate_private_key(ec.SECP256R1())
        self.server_random=os.urandom(16)
        self.session_key=None
        self.link_key=None
        self.device_name="TestServer"
        self.device_class="0x200404"

    def generate_link_key(self,client_random):
        hkdf=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b"bluetooth-link-key")
        material=self.server_random+client_random
        return hkdf.derive(material)
    
    def derive_session_key(self,shared_secret):
        hkdf=HKDF(algorithm=hashes.SHA256(),length=32,salt=self.link_key,info=b"bluetooth-session-key")
        return hkdf.derive(shared_secret)
    
    def encrypt_data(self,data):
        iv=os.urandom(16)
        padder=padding.PKCS7(128).padder()
        padded_data=padder.update(data.encode())+padder.finalize()
        cipher=Cipher(algorithms.AES(self.session_key),modes.CBC(iv))
        encryptor=cipher.encryptor()
        encrypted=encryptor.update(padded_data)+encryptor.finalize()
        return{'iv':base64.b64encode(iv).decode(),'data':base64.b64encode(encrypted).decode()}
    
    def decrypt_data(self,encrypted_dict):
        iv=base64.b64decode(encrypted_dict['iv'])
        encrypted=base64.b64decode(encrypted_dict['data'])
        cipher=Cipher(algorithms.AES(self.session_key),modes.CBC(iv))
        decryptor=cipher.decryptor()
        padded_data=decryptor.update(encrypted)+decryptor.finalize()
        unpadder=padding.PKCS7(128).unpadder()
        data=unpadder.update(padded_data)+unpadder.finalize()
        return data.decode()
    
    def run(self,pin_code="123456"):
        print(f"Bluetooth server starting on {self.host}:{self.port}")
        print(f"Device: {self.device_name} ({self.device_class})")
        client,addr=self.socket.accept()
        print(f"Client connected: {addr}")
        try:
            discovery_msg={'type':'DISCOVERY','name':self.device_name,'class':self.device_class}
            client.send(json.dumps(discovery_msg).encode())
            client_info=json.loads(client.recv(4096).decode())
            client_random=base64.b64decode(client_info['random'])
            self.link_key=self.generate_link_key(client_random)
            link_msg={'type':'LINK_INFO','random':base64.b64encode(self.server_random).decode()}
            client.send(json.dumps(link_msg).encode())
            auth_msg=json.loads(client.recv(4096).decode())
            if auth_msg['pin']!=pin_code:raise Exception("PIN code mismatch!")
            public_bytes=self.private_key.public_key().public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            key_msg={'type':'KEY_EXCHANGE','public_key':base64.b64encode(public_bytes).decode()}
            client.send(json.dumps(key_msg).encode())
            client_key_msg=json.loads(client.recv(4096).decode())
            client_public_key=serialization.load_der_public_key(base64.b64decode(client_key_msg['public_key']))
            shared_secret=self.private_key.exchange(ec.ECDH(),client_public_key)
            self.session_key=self.derive_session_key(shared_secret)
            print("Pairing completed successfully!")
            while True:
                encrypted_msg=json.loads(client.recv(4096).decode())
                if not encrypted_msg:break
                msg=self.decrypt_data(encrypted_msg)
                print(f"Received: {msg}")
                response=f"Echo: {msg}"
                client.send(json.dumps(self.encrypt_data(response)).encode())
                if msg.lower()=="quit":break
        except Exception as e:
            print(f"Error during pairing: {e}")
        finally:
            client.close()
            self.socket.close()
            
if _name=="main_":
    server=BluetoothServer()
    server.run()