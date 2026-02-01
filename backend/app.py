from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import jwt
import os
import hashlib
import secrets
import base64
import json
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

# Configuración - USANDO SQLite
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-123')
app.config['JWT_SECRET'] = os.getenv('JWT_SECRET', 'jwt-secret-key-456')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cryptoguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==================== MODELOS ====================
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    public_key = db.Column(db.Text)
    private_key = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<User {self.username}>'

class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content_encrypted = db.Column(db.Text, nullable=False)
    encryption_type = db.Column(db.String(20), nullable=False)
    encryption_key = db.Column(db.Text)
    iv = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'encryption_type': self.encryption_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<Document {self.title}>'

class CryptoLog(db.Model):
    __tablename__ = 'crypto_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    algorithm = db.Column(db.String(50))
    input_data = db.Column(db.Text)
    output_data = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'algorithm': self.algorithm,
            'input_data': self.input_data,
            'output_data': self.output_data,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
    
    def __repr__(self):
        return f'<CryptoLog {self.action} - {self.algorithm}>'

# ==================== FUNCIONES CRIPTOGRÁFICAS ====================
def get_aes_key():
    """Obtener clave AES"""
    key = os.getenv('AES_KEY', '32-bytes-key-for-aes-256-cbc-test')
    # Asegurar que la clave tenga 32 bytes
    if len(key) < 32:
        key = key.ljust(32, '0')
    elif len(key) > 32:
        key = key[:32]
    return key.encode()

def encrypt_aes(plaintext):
    """Cifrado AES-256 CBC"""
    try:
        iv = secrets.token_bytes(16)
        cipher = Cipher(
            algorithms.AES(get_aes_key()),
            modes.CBC(iv)
        )
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return {
            'encrypted': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }
        
    except Exception as e:
        raise Exception(f"Error en cifrado AES: {str(e)}")

def decrypt_aes(ciphertext_b64, iv_b64):
    """Descifrado AES-256 CBC"""
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        
        cipher = Cipher(
            algorithms.AES(get_aes_key()),
            modes.CBC(iv)
        )
        
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
        
    except Exception as e:
        raise Exception(f"Error en descifrado AES: {str(e)}")

def generate_rsa_keys():
    """Generar par de llaves RSA"""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem.decode('utf-8'), private_pem.decode('utf-8')
        
    except Exception as e:
        raise Exception(f"Error generando llaves RSA: {str(e)}")

def encrypt_rsa(plaintext, public_key_pem):
    """Cifrado RSA"""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        
        # RSA tiene límite de tamaño, dividir si es muy largo
        max_length = 190  # Para RSA-2048 con OAEP
        if len(plaintext) > max_length:
            # Para texto largo, mejor usar AES y cifrar la clave con RSA
            raise ValueError(f"Texto muy largo para RSA. Máximo {max_length} caracteres")
        
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            'encrypted': base64.b64encode(ciphertext).decode('utf-8')
        }
        
    except Exception as e:
        raise Exception(f"Error en cifrado RSA: {str(e)}")

def decrypt_rsa(ciphertext_b64, private_key_pem):
    """Descifrado RSA"""
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext.decode('utf-8')
        
    except Exception as e:
        raise Exception(f"Error en descifrado RSA: {str(e)}")

def hash_password(password):
    """Hash de contraseña con salt"""
    try:
        salt = secrets.token_hex(16)
        password_salt = password + salt
        hash_object = hashlib.sha256(password_salt.encode())
        password_hash = hash_object.hexdigest()
        
        return password_hash, salt
        
    except Exception as e:
        raise Exception(f"Error generando hash: {str(e)}")

def verify_password(password, stored_hash, salt):
    """Verificar contraseña"""
    try:
        password_salt = password + salt
        hash_object = hashlib.sha256(password_salt.encode())
        computed_hash = hash_object.hexdigest()
        
        return computed_hash == stored_hash
        
    except Exception as e:
        raise Exception(f"Error verificando contraseña: {str(e)}")

def encrypt_vigenere(plaintext, key):
    """Cifrado Vigenère"""
    try:
        # Convertir a mayúsculas
        plaintext = plaintext.upper()
        key = key.upper()
        
        result = []
        key_index = 0
        
        for char in plaintext:
            if 'A' <= char <= 'Z':
                shift = ord(key[key_index % len(key)]) - ord('A')
                encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
                result.append(encrypted_char)
                key_index += 1
            else:
                result.append(char)
        
        return {
            'encrypted': ''.join(result),
            'key': key
        }
        
    except Exception as e:
        raise Exception(f"Error en cifrado Vigenère: {str(e)}")

def decrypt_vigenere(ciphertext, key):
    """Descifrado Vigenère"""
    try:
        ciphertext = ciphertext.upper()
        key = key.upper()
        
        result = []
        key_index = 0
        
        for char in ciphertext:
            if 'A' <= char <= 'Z':
                shift = ord(key[key_index % len(key)]) - ord('A')
                decrypted_char = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
                result.append(decrypted_char)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
        
    except Exception as e:
        raise Exception(f"Error en descifrado Vigenère: {str(e)}")

def sha256_hash(text):
    """Hash SHA-256 simple"""
    try:
        hash_object = hashlib.sha256(text.encode())
        return hash_object.hexdigest()
    except Exception as e:
        raise Exception(f"Error generando hash SHA-256: {str(e)}")

# ==================== MIDDLEWARE DE AUTENTICACIÓN ====================
def token_required(f):
    from functools import wraps
    
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Obtener token del header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token es requerido'}), 401
        
        try:
            # Decodificar token
            data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'Usuario no encontrado'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# ==================== RUTAS DE LA API ====================

@app.route('/')
def index():
    return jsonify({
        'message': 'CryptoGuard Platform API',
        'version': '1.0.0',
        'endpoints': {
            'GET /api/health': 'Health check',
            'POST /api/register': 'Registrar usuario',
            'POST /api/login': 'Iniciar sesión',
            'POST /api/crypto/encrypt': 'Cifrar texto',
            'POST /api/crypto/decrypt': 'Descifrar texto',
            'GET /api/documents': 'Listar documentos',
            'POST /api/documents': 'Crear documento',
            'GET /api/documents/<id>': 'Obtener documento',
            'GET /api/logs': 'Obtener logs',
            'GET /api/user/profile': 'Perfil de usuario'
        }
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'CryptoGuard Platform API',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'connected' if db.engine else 'disconnected'
    }), 200

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Validación
        if not username or not email or not password:
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        # Verificar si usuario ya existe
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'error': 'El nombre de usuario ya existe'}), 400
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return jsonify({'error': 'El correo electrónico ya existe'}), 400
        
        # Generar hash de contraseña
        password_hash, salt = hash_password(password)
        
        # Generar llaves RSA
        public_key, private_key = generate_rsa_keys()
        
        # Crear usuario
        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            salt=salt,
            public_key=public_key,
            private_key=private_key
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Generar token JWT
        token = jwt.encode({
            'user_id': new_user.id,
            'username': new_user.username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['JWT_SECRET'], algorithm='HS256')
        
        return jsonify({
            'success': True,
            'message': 'Usuario registrado exitosamente',
            'token': token,
            'user': new_user.to_dict()
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña son requeridos'}), 400
        
        # Buscar usuario
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Verificar contraseña
        if verify_password(password, user.password_hash, user.salt):
            # Generar token JWT
            token = jwt.encode({
                'user_id': user.id,
                'username': user.username,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['JWT_SECRET'], algorithm='HS256')
            
            return jsonify({
                'success': True,
                'message': 'Inicio de sesión exitoso',
                'token': token,
                'user': user.to_dict()
            }), 200
        else:
            return jsonify({'error': 'Contraseña incorrecta'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/crypto/encrypt', methods=['POST'])
@token_required
def encrypt_text(current_user):
    try:
        data = request.json
        text = data.get('text', '').strip()
        algorithm = data.get('algorithm', '').upper()
        key = data.get('key', '').strip()
        
        if not text:
            return jsonify({'error': 'El texto es requerido'}), 400
        
        if not algorithm:
            return jsonify({'error': 'El algoritmo es requerido'}), 400
        
        result = {}
        algorithm_name = ''
        
        if algorithm == 'AES':
            aes_result = encrypt_aes(text)
            result = {
                'encrypted': aes_result['encrypted'],
                'iv': aes_result['iv']
            }
            algorithm_name = 'AES-256-CBC'
            
        elif algorithm == 'RSA':
            # Para RSA, texto debe ser corto
            if len(text) > 190:
                return jsonify({'error': 'Texto muy largo para RSA. Use AES para textos largos'}), 400
            
            rsa_result = encrypt_rsa(text, current_user.public_key)
            result = {
                'encrypted': rsa_result['encrypted']
            }
            algorithm_name = 'RSA-2048-OAEP'
            
        elif algorithm == 'VIGENERE':
            if not key:
                return jsonify({'error': 'Se requiere una clave para Vigenère'}), 400
            
            vigenere_result = encrypt_vigenere(text, key)
            result = {
                'encrypted': vigenere_result['encrypted'],
                'key': vigenere_result['key']
            }
            algorithm_name = 'Vigenère'
            
        elif algorithm == 'SHA256':
            hash_value = sha256_hash(text)
            result = {
                'hash': hash_value
            }
            algorithm_name = 'SHA-256'
            
        else:
            return jsonify({'error': f'Algoritmo no soportado: {algorithm}'}), 400
        
        # Registrar en logs
        log = CryptoLog(
            user_id=current_user.id,
            action='ENCRYPT',
            algorithm=algorithm_name,
            input_data=text[:100] + '...' if len(text) > 100 else text,
            output_data=str(result)[:100] + '...'
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'algorithm': algorithm_name,
            'result': result,
            'message': f'Texto cifrado con {algorithm_name}'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error en cifrado: {str(e)}'}), 500

@app.route('/api/crypto/decrypt', methods=['POST'])
@token_required
def decrypt_text(current_user):
    try:
        data = request.json
        algorithm = data.get('algorithm', '').upper()
        
        if not algorithm:
            return jsonify({'error': 'El algoritmo es requerido'}), 400
        
        # SHA256 NO ES DESCIFRABLE - es solo hash
        if algorithm == 'SHA256':
            return jsonify({
                'success': False,
                'error': 'SHA-256 es una función hash, no se puede descifrar'
            }), 400
        
        result = ''
        algorithm_name = ''
        
        if algorithm == 'AES':
            encrypted_text = data.get('encrypted_text', '').strip()
            iv = data.get('iv', '').strip()
            
            if not encrypted_text:
                return jsonify({'error': 'El texto cifrado es requerido para AES'}), 400
            if not iv:
                return jsonify({'error': 'El IV es requerido para AES'}), 400
            
            result = decrypt_aes(encrypted_text, iv)
            algorithm_name = 'AES-256-CBC'
            
        elif algorithm == 'RSA':
            encrypted_text = data.get('encrypted_text', '').strip()
            
            if not encrypted_text:
                return jsonify({'error': 'El texto cifrado es requerido para RSA'}), 400
            
            result = decrypt_rsa(encrypted_text, current_user.private_key)
            algorithm_name = 'RSA-2048-OAEP'
            
        elif algorithm == 'VIGENERE':
            encrypted_text = data.get('encrypted_text', '').strip()
            key = data.get('key', '').strip()
            
            if not encrypted_text:
                return jsonify({'error': 'El texto cifrado es requerido para Vigenère'}), 400
            if not key:
                return jsonify({'error': 'La clave es requerida para Vigenère'}), 400
            
            result = decrypt_vigenere(encrypted_text, key)
            algorithm_name = 'Vigenère'
            
        else:
            return jsonify({'error': f'Algoritmo no soportado para descifrado: {algorithm}'}), 400
        
        # Registrar en logs
        log = CryptoLog(
            user_id=current_user.id,
            action='DECRYPT',
            algorithm=algorithm_name,
            input_data=encrypted_text[:100] + '...' if len(encrypted_text) > 100 else encrypted_text,
            output_data=result[:100] + '...' if len(result) > 100 else result
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'algorithm': algorithm_name,
            'result': result,
            'message': f'Texto descifrado con {algorithm_name}'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error en descifrado: {str(e)}'}), 500

@app.route('/api/crypto/test', methods=['POST'])
def test_crypto():
    """Endpoint de prueba sin autenticación"""
    try:
        data = request.json
        test_type = data.get('type', 'all')
        
        results = {}
        test_text = "Hola Mundo Crypto123"
        
        if test_type in ['all', 'aes']:
            # Test AES
            aes_result = encrypt_aes(test_text)
            aes_decrypted = decrypt_aes(aes_result['encrypted'], aes_result['iv'])
            results['AES'] = {
                'original': test_text,
                'encrypted': aes_result['encrypted'][:50] + '...',
                'iv': aes_result['iv'],
                'decrypted': aes_decrypted,
                'success': test_text == aes_decrypted
            }
        
        if test_type in ['all', 'vigenere']:
            # Test Vigenère
            key = "SECRETO"
            vigenere_result = encrypt_vigenere(test_text, key)
            vigenere_decrypted = decrypt_vigenere(vigenere_result['encrypted'], key)
            results['Vigenère'] = {
                'original': test_text,
                'encrypted': vigenere_result['encrypted'],
                'key': key,
                'decrypted': vigenere_decrypted,
                'success': test_text.upper() == vigenere_decrypted
            }
        
        if test_type in ['all', 'sha256']:
            # Test SHA256
            hash_value = sha256_hash(test_text)
            results['SHA256'] = {
                'original': test_text,
                'hash': hash_value,
                'length': len(hash_value)
            }
        
        if test_type in ['all', 'rsa']:
            # Test RSA
            public_key, private_key = generate_rsa_keys()
            rsa_result = encrypt_rsa(test_text, public_key)
            rsa_decrypted = decrypt_rsa(rsa_result['encrypted'], private_key)
            results['RSA'] = {
                'original': test_text,
                'encrypted': rsa_result['encrypted'][:50] + '...',
                'decrypted': rsa_decrypted,
                'success': test_text == rsa_decrypted
            }
        
        return jsonify({
            'success': True,
            'tests': results,
            'message': 'Pruebas criptográficas completadas'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error en pruebas: {str(e)}'}), 500

@app.route('/api/documents', methods=['GET'])
@token_required
def get_documents(current_user):
    try:
        documents = Document.query.filter_by(user_id=current_user.id).all()
        
        return jsonify({
            'success': True,
            'documents': [doc.to_dict() for doc in documents],
            'count': len(documents)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents', methods=['POST'])
@token_required
def create_document(current_user):
    try:
        data = request.json
        title = data.get('title')
        content = data.get('content')
        encryption_type = data.get('encryption_type', 'AES').upper()
        key = data.get('key', '')
        
        if not title or not content:
            return jsonify({'error': 'Título y contenido son requeridos'}), 400
        
        encrypted_content = ''
        encryption_key = ''
        iv = ''
        
        if encryption_type == 'AES':
            aes_result = encrypt_aes(content)
            encrypted_content = aes_result['encrypted']
            iv = aes_result['iv']
            
        elif encryption_type == 'RSA':
            if len(content) > 190:
                return jsonify({'error': 'Contenido muy largo para RSA. Use AES'}), 400
            rsa_result = encrypt_rsa(content, current_user.public_key)
            encrypted_content = rsa_result['encrypted']
            
        elif encryption_type == 'VIGENERE':
            if not key:
                return jsonify({'error': 'Se requiere una clave para Vigenère'}), 400
            vigenere_result = encrypt_vigenere(content, key)
            encrypted_content = vigenere_result['encrypted']
            encryption_key = vigenere_result['key']
            
        else:
            return jsonify({'error': 'Tipo de cifrado no soportado'}), 400
        
        # Crear documento
        new_document = Document(
            user_id=current_user.id,
            title=title,
            content_encrypted=encrypted_content,
            encryption_type=encryption_type,
            encryption_key=encryption_key,
            iv=iv
        )
        
        db.session.add(new_document)
        db.session.commit()
        
        # Registrar log
        log = CryptoLog(
            user_id=current_user.id,
            action='CREATE_DOCUMENT',
            algorithm=encryption_type,
            input_data=content[:50] + '...' if len(content) > 50 else content,
            output_data=f"Documento creado: {title}"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Documento creado exitosamente',
            'document_id': new_document.id
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents/<int:doc_id>', methods=['GET'])
@token_required
def get_document(current_user, doc_id):
    try:
        document = Document.query.filter_by(id=doc_id, user_id=current_user.id).first()
        
        if not document:
            return jsonify({'error': 'Documento no encontrado'}), 404
        
        # Descifrar contenido
        decrypted_content = ''
        
        if document.encryption_type == 'AES':
            decrypted_content = decrypt_aes(document.content_encrypted, document.iv)
            
        elif document.encryption_type == 'RSA':
            decrypted_content = decrypt_rsa(document.content_encrypted, current_user.private_key)
            
        elif document.encryption_type == 'VIGENERE':
            decrypted_content = decrypt_vigenere(document.content_encrypted, document.encryption_key)
        
        return jsonify({
            'success': True,
            'document': {
                **document.to_dict(),
                'content': decrypted_content
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@token_required
def delete_document(current_user, doc_id):
    try:
        document = Document.query.filter_by(id=doc_id, user_id=current_user.id).first()
        
        if not document:
            return jsonify({'error': 'Documento no encontrado'}), 404
        
        db.session.delete(document)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Documento eliminado exitosamente'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
@token_required
def get_logs(current_user):
    try:
        logs = CryptoLog.query.filter_by(user_id=current_user.id)\
            .order_by(CryptoLog.timestamp.desc())\
            .limit(50)\
            .all()
        
        return jsonify({
            'success': True,
            'logs': [log.to_dict() for log in logs],
            'count': len(logs)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    try:
        return jsonify({
            'success': True,
            'user': current_user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== INICIALIZACIÓN ====================
def create_tables():
    """Crear tablas y usuario demo"""
    with app.app_context():
        # Crear todas las tablas
        db.create_all()
        print("✅ Tablas de base de datos creadas")
        
        # Crear usuario demo si no existe
        demo_user = User.query.filter_by(username='demo').first()
        if not demo_user:
            print("🔧 Creando usuario de demostración...")
            password_hash, salt = hash_password('demodemo')
            public_key, private_key = generate_rsa_keys()
            
            demo_user = User(
                username='demo',
                email='demo@cryptoguard.com',
                password_hash=password_hash,
                salt=salt,
                public_key=public_key,
                private_key=private_key
            )
            
            db.session.add(demo_user)
            db.session.commit()
            
            print("✅ Usuario demo creado:")
            print(f"   Usuario: demo")
            print(f"   Contraseña: demodemo")
            print(f"   Email: demo@cryptoguard.com")
        
        print("\n🎉 Sistema listo para usar!")

if __name__ == '__main__':
    # Crear tablas al iniciar
    create_tables()
    
    print("\n🚀 Servidor CryptoGuard iniciado")
    print("📡 API disponible en: http://localhost:5000")
    print("\n📋 Endpoints principales:")
    print("   GET  /                    - Documentación de API")
    print("   GET  /api/health          - Estado del sistema")
    print("   POST /api/register        - Registrar usuario")
    print("   POST /api/login           - Iniciar sesión")
    print("   POST /api/crypto/encrypt  - Cifrar texto")
    print("   POST /api/crypto/decrypt  - Descifrar texto")
    print("   POST /api/crypto/test     - Pruebas criptográficas")
    print("\n👤 Usuario demo: demo / demodemo")
    
    app.run(debug=True, host='0.0.0.0', port=5000)