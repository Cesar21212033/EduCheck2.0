-- Script para crear un usuario administrador
-- Ejecutar este script después de tener al menos un usuario en la base de datos

-- Opción 1: Crear un nuevo usuario admin directamente
-- Reemplaza 'admin' con el username que desees, 'admin@ejemplo.com' con el email, 
-- 'Nombre Admin' con el nombre completo, y 'password123' con la contraseña deseada
-- (La contraseña se guardará hasheada automáticamente)

-- Hash válido para la contraseña 'admin123'
-- Generado con: python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('admin123'))"
INSERT INTO usuarios (username, email, password_hash, nombre_completo, rol, activo, creado_en)
VALUES (
    'admin',
    'admin@tectijuana.edu.mx',
    'pbkdf2:sha256:600000$4VfADb7eOdJ5gQ2W$58bf51cb43f4979f06d8d1f873c2197bc394c037b4ce851bd370c1d3fd5e79f7',
    'Administrador del Sistema',
    'admin',
    1,
    NOW()
);

-- Opción 2: Convertir un usuario existente a admin
-- Reemplaza 'nombre_usuario' con el username del usuario que quieres convertir a admin
-- UPDATE usuarios SET rol = 'admin' WHERE username = 'nombre_usuario';

-- Para generar un hash de contraseña en Python, ejecuta:
-- python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('tu_contraseña'))"

