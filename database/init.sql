-- Crear base de datos
CREATE DATABASE cryptodb;

-- Conectar a la base de datos
\c cryptodb;

-- Crear usuario para la aplicación
CREATE USER cryptouser WITH PASSWORD 'SecurePass123';

-- Otorgar privilegios
GRANT ALL PRIVILEGES ON DATABASE cryptodb TO cryptouser;

-- Crear tablas (estas se crearán automáticamente con SQLAlchemy, pero aquí está el script SQL directo)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    public_key TEXT,
    private_key_encrypted TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    content_encrypted TEXT NOT NULL,
    encryption_type VARCHAR(20) NOT NULL,
    encryption_key TEXT,
    iv TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE crypto_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    algorithm VARCHAR(50),
    input_data TEXT,
    output_data TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Crear índices para mejorar el rendimiento
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_documents_user_id ON documents(user_id);
CREATE INDEX idx_documents_encryption_type ON documents(encryption_type);
CREATE INDEX idx_crypto_logs_user_id ON crypto_logs(user_id);
CREATE INDEX idx_crypto_logs_timestamp ON crypto_logs(timestamp);

-- Otorgar permisos al usuario
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cryptouser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cryptouser;