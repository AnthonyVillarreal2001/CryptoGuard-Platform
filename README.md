# CryptoGuard Platform

## 🚀 Descripción
Plataforma web completa para implementación y prueba de técnicas criptográficas desarrollada como proyecto final de Ingeniería de Seguridad de Software. Implementa 4 algoritmos criptográficos en un sistema web funcional con autenticación segura y almacenamiento de documentos cifrados.

## ✨ Características Principales

### 🔐 Algoritmos Criptográficos Implementados
- **AES-256 (CBC Mode)** - Cifrado simétrico avanzado
- **RSA-2048 (OAEP Padding)** - Cifrado asimétrico seguro  
- **Vigenère** - Cifrado clásico polialfabético
- **SHA-256** - Función hash criptográfica

### 🛡️ Características de Seguridad
- ✅ Autenticación JWT con tokens seguros
- ✅ Contraseñas con hash SHA-256 + salt
- ✅ Almacenamiento cifrado de documentos
- ✅ Generación automática de llaves RSA por usuario
- ✅ Logs de auditoría de todas las operaciones
- ✅ Protección contra inyecciones SQL
- ✅ Validación de entrada de datos

### 💻 Funcionalidades del Sistema
- **Sistema CRUD completo** para documentos
- **API RESTful** con Flask
- **Interfaz web moderna** y responsive
- **Base de datos SQLite** (sin dependencias externas)
- **Dashboard interactivo** con estadísticas
- **Herramientas criptográficas** en tiempo real
- **Historial de actividades** detallado
- **Sistema de pruebas** integrado

## 📋 Requisitos del Sistema

### Software Requerido
- **Python 3.8 o superior**
- **Navegador web moderno** (Chrome 90+, Firefox 88+, Edge 90+)
- **Git** (opcional, para clonar el repositorio)

### Dependencias Python
Todas las dependencias están en `backend/requirements.txt`:
- Flask 2.3.3 - Framework web
- Flask-CORS 4.0.0 - Soporte CORS
- Flask-SQLAlchemy 3.0.5 - ORM para base de datos
- cryptography 41.0.5 - Implementaciones criptográficas
- PyJWT 2.8.0 - Tokens JWT
- python-dotenv 1.0.0 - Manejo de variables de entorno

## 🚀 Instalación Rápida (Windows)

### Paso 1: Clonar o descargar el proyecto
```cmd
# Crear carpeta del proyecto
mkdir D:\Proyectos\CryptoGuard
cd D:\Proyectos\CryptoGuard

# Descargar los archivos o copiarlos manualmente
# Estructura necesaria:
# CryptoGuard/
# ├── backend/
# └── frontend/
```

### Paso 2: Configurar el entorno virtual
```cmd
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
venv\Scripts\activate.bat

# Verificar que esté activado (debería mostrar (venv))
(venv) D:\Proyectos\CryptoGuard>
```

### Paso 3: Instalar dependencias del backend
```cmd
cd backend
pip install --upgrade pip
pip install -r requirements.txt
```

### Paso 4: Configurar variables de entorno
Crear archivo `backend/.env` con:
```env
SECRET_KEY=mi_clave_secreta_para_flask_app_2024
JWT_SECRET=mi_jwt_secret_key_para_tokens_2024
AES_KEY=32_bytes_key_for_aes_256_cbc_123456
```

### Paso 5: Ejecutar el backend
```cmd
python app.py
```
**Verificación:** Abrir http://localhost:5000/api/health

### Paso 6: Ejecutar el frontend
En otra terminal:
```cmd
cd frontend
python -m http.server 8000
```

### Paso 7: Acceder a la aplicación
1. **Frontend:** http://localhost:8000
2. **Backend API:** http://localhost:5000
3. **API Docs:** http://localhost:5000/

## 📁 Estructura del Proyecto

```
CryptoGuard-Platform/
├── backend/                   # Código del servidor
│   ├── app.py                # Aplicación Flask principal
│   ├── requirements.txt      # Dependencias Python
│   ├── .env                 # Variables de entorno
│   └── cryptoguard.db       # Base de datos SQLite (se crea automáticamente)
├── frontend/                 # Interfaz web
│   ├── index.html           # Página de login/registro
│   └── dashboard.html       # Dashboard principal
└── README.md                # Este archivo
```

## 🔧 Configuración de Usuarios

### Usuario de Demostración
El sistema crea automáticamente un usuario demo:
- **Usuario:** `demo`
- **Contraseña:** `demodemo`
- **Email:** `demo@cryptoguard.com`

### Registrar Nuevo Usuario
1. Acceder a http://localhost:8000
2. Hacer clic en "Registrarse"
3. Completar formulario:
   - Usuario: mínimo 3 caracteres
   - Email: formato válido
   - Contraseña: mínimo 6 caracteres
4. El sistema generará automáticamente un par de llaves RSA

## 📚 Guía de Uso

### 1. Autenticación
- **Login:** Acceder con usuario y contraseña
- **Token JWT:** Se genera automáticamente y se guarda en localStorage
- **Sesión:** Válida por 24 horas
- **Logout:** Cerrar sesión desde el dashboard

### 2. Herramientas Criptográficas
Acceder a la sección "🔐 Cifrado/Descifrado" en el dashboard:

#### 🔑 AES-256
- **Cifrar:** Texto → Texto cifrado + IV
- **Descifrar:** Requiere texto cifrado + IV
- **Características:** Cifrado simétrico, ideal para textos largos

#### 🗝️ RSA-2048
- **Cifrar:** Texto corto (<190 chars) → Texto cifrado
- **Descifrar:** Requiere texto cifrado
- **Características:** Cifrado asimétrico, cada usuario tiene su par de llaves

#### 🏛️ Vigenère
- **Cifrar:** Texto + Clave → Texto cifrado
- **Descifrar:** Requiere texto cifrado + misma clave
- **Características:** Cifrado clásico, solo letras mayúsculas

#### #️⃣ SHA-256
- **Hash:** Texto → Hash de 64 caracteres
- **No descifrable:** Función hash unidireccional
- **Características:** Verificación de integridad

### 3. Gestión de Documentos
- **Crear:** Nuevo documento con cifrado seleccionado
- **Listar:** Ver todos los documentos del usuario
- **Ver:** Descifrar y mostrar contenido del documento
- **Eliminar:** Borrar documentos

### 4. Historial de Actividades
- Registro automático de todas las operaciones
- Filtrado por usuario
- Ordenado por fecha más reciente
- Límite de 50 registros visibles

### 5. Pruebas del Sistema
Acceder a la sección "🧪 Pruebas" para:
- Verificar funcionamiento de todos los algoritmos
- Ejecutar pruebas individuales
- Diagnosticar problemas

## 🔌 Endpoints de la API

### Públicos (Sin autenticación)
- `GET /` - Documentación de la API
- `GET /api/health` - Estado del sistema
- `POST /api/register` - Registrar nuevo usuario
- `POST /api/login` - Iniciar sesión
- `POST /api/crypto/test` - Pruebas criptográficas

### Protegidos (Requieren token JWT)
- `GET /api/user/profile` - Perfil de usuario
- `POST /api/crypto/encrypt` - Cifrar texto
- `POST /api/crypto/decrypt` - Descifrar texto
- `GET /api/documents` - Listar documentos
- `POST /api/documents` - Crear documento
- `GET /api/documents/<id>` - Obtener documento
- `DELETE /api/documents/<id>` - Eliminar documento
- `GET /api/logs` - Obtener logs de actividad

### Ejemplos de uso con curl

#### Registrar usuario:
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"test123"}'
```

#### Login:
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"demo","password":"demodemo"}'
```

#### Cifrar texto (requiere token):
```bash
curl -X POST http://localhost:5000/api/crypto/encrypt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TU_TOKEN_JWT" \
  -d '{"text":"Hola Mundo","algorithm":"AES"}'
```

## 🧪 Pruebas y Verificación

### Pruebas Automáticas
1. Acceder a la sección "🧪 Pruebas" en el dashboard
2. Hacer clic en "Ejecutar Todas las Pruebas"
3. Verificar que todas las pruebas sean exitosas

### Verificación Manual
```bash
# Verificar estado del backend
curl http://localhost:5000/api/health

# Probar cifrado AES sin autenticación
curl -X POST http://localhost:5000/api/crypto/test \
  -H "Content-Type: application/json" \
  -d '{"type":"aes"}'
```

### Resultados Esperados
- **AES-256:** Cifrado/descifrado exitoso
- **RSA-2048:** Cifrado/descifrado exitoso para textos cortos
- **Vigenère:** Cifrado/descifrado exitoso con clave
- **SHA-256:** Hash generado correctamente (64 chars hex)

## 🐛 Solución de Problemas Comunes

### Problema: "No se puede encontrar el módulo"
```cmd
# Solución: Reinstalar dependencias
venv\Scripts\activate.bat
pip install --upgrade -r backend\requirements.txt
```

### Problema: Puerto 5000 en uso
```python
# En app.py, cambiar puerto:
app.run(debug=True, host='0.0.0.0', port=5001)
```

### Problema: CORS en frontend
- Asegurarse de usar `http://localhost:8000` (no `file://`)
- Verificar que el backend esté ejecutándose

### Problema: Error de base de datos
```cmd
# Eliminar base de datos corrupta
cd backend
del cryptoguard.db
python app.py  # Se creará nueva
```

### Problema: "Token expirado"
- Cerrar sesión y volver a iniciar
- Verificar que la hora del sistema sea correcta

## 📊 Características Técnicas

### Backend (Flask)
- **Framework:** Flask 2.3.3
- **Base de datos:** SQLite con SQLAlchemy
- **Autenticación:** JWT con PyJWT
- **Criptografía:** Biblioteca cryptography
- **CORS:** Habilitado para desarrollo
- **Puerto:** 5000 por defecto

### Frontend
- **Tecnologías:** HTML5, CSS3, JavaScript vanilla
- **Diseño:** Responsive y moderno
- **Comunicación:** Fetch API con JSON
- **Almacenamiento:** localStorage para tokens
- **Servidor:** Python http.server (puerto 8000)

### Seguridad Implementada
- ✅ Contraseñas con hash y salt
- ✅ Tokens JWT con expiración
- ✅ Validación de entrada
- ✅ Protección contra XSS básica
- ✅ Logs de auditoría
- ✅ Cifrado de datos sensibles

## 🔄 Flujo de Trabajo Recomendado

### Para Desarrollo
1. Activar entorno virtual
2. Ejecutar backend en terminal 1
3. Ejecutar frontend en terminal 2
4. Usar las herramientas del dashboard para pruebas
5. Ver logs en consola del backend

### Para Pruebas de Usuario
1. Registrar nuevo usuario o usar demo
2. Probar cada algoritmo individualmente
3. Crear documentos con diferentes cifrados
4. Verificar historial de actividades
5. Ejecutar pruebas automáticas

## 🎯 Objetivos de Aprendizaje Cubiertos

### Criptografía Práctica
- Implementación de algoritmos simétricos/asimétricos
- Uso de funciones hash con salt
- Manejo seguro de llaves criptográficas
- Cifrado/descifrado en aplicaciones reales

### Desarrollo Web Seguro
- Autenticación y autorización
- Almacenamiento seguro de datos
- Protección de endpoints API
- Logs y auditoría de seguridad

### Ingeniería de Software
- Arquitectura cliente-servidor
- API RESTful con Flask
- Manejo de base de datos
- Interfaz de usuario responsive

## 📈 Estado del Proyecto

### ✅ Completado
- [x] Sistema de autenticación completo
- [x] 4 algoritmos criptográficos implementados
- [x] CRUD de documentos con cifrado
- [x] API RESTful funcional
- [x] Interfaz web completa
- [x] Base de datos SQLite
- [x] Sistema de logs y auditoría
- [x] Pruebas automáticas integradas

### 🔄 En Desarrollo
- [ ] Exportación/importación de documentos
- [ ] Compartición segura de documentos
- [ ] Autenticación de dos factores
- [ ] Panel de administración
- [ ] Más algoritmos criptográficos

## 📝 Notas Importantes

### Para Producción
1. Cambiar claves secretas en `.env`
2. Usar base de datos PostgreSQL/MySQL
3. Configurar HTTPS con certificado válido
4. Implementar rate limiting
5. Agregar más validaciones de seguridad
6. Usar entorno de producción (debug=False)

### Limitaciones Actuales
- RSA solo para textos cortos (<190 caracteres)
- Vigenère solo con letras mayúsculas
- SQLite no recomendado para producción
- Sin recuperación de contraseña
- Sin confirmación por email

## 🤝 Contribución

### Estructura para Nuevos Algoritmos
```python
# En app.py, agregar:
def encrypt_nuevo_algoritmo(texto, clave):
    # Implementación aquí
    return resultado

def decrypt_nuevo_algoritmo(texto_cifrado, clave):
    # Implementación aquí
    return resultado

# Agregar a las rutas de /api/crypto/encrypt y /decrypt
```

### Mejoras Pendientes
1. Agregar más algoritmos clásicos (César, Playfair, etc.)
2. Implementar ECC (Elliptic Curve Cryptography)
3. Agregar firma digital
4. Implementar perfect forward secrecy
5. Crear aplicación móvil

## 📄 Licencia
Este proyecto está desarrollado con fines educativos para el curso de Ingeniería de Seguridad de Software. Libre para uso académico.

## 👥 Autores
- [Tu Nombre]
- [Nombre Compañero 1]
- [Nombre Compañero 2]

## 🙏 Agradecimientos
- Dr. Walter Fuertes, PhD por la guía y supervisión
- Universidad [Nombre] por los recursos
- Comunidad de código abierto por las bibliotecas utilizadas

---

**🎉 ¡Sistema listo para usar!** Accede a http://localhost:8000 y comienza a explorar las técnicas criptográficas implementadas.