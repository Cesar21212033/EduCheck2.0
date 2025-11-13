-- Script para corregir usuarios con password_hash inválido o vacío
-- Ejecutar este script si tienes usuarios con problemas de autenticación

-- Verificar usuarios con password_hash vacío o NULL
SELECT id, username, email, password_hash, rol 
FROM usuarios 
WHERE password_hash IS NULL OR password_hash = '' OR password_hash NOT LIKE 'pbkdf2:%';

-- Opción 1: Actualizar un usuario específico con un hash válido
-- Reemplaza 'nombre_usuario' con el username y 'nueva_contraseña' con la contraseña deseada
-- Primero genera el hash en Python:
-- python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('nueva_contraseña'))"
-- Luego ejecuta:
-- UPDATE usuarios SET password_hash = 'hash_generado' WHERE username = 'nombre_usuario';

-- Opción 2: Resetear contraseña del admin a 'admin123'
-- Hash para 'admin123': pbkdf2:sha256:600000$4VfADb7eOdJ5gQ2W$58bf51cb43f4979f06d8d1f873c2197bc394c037b4ce851bd370c1d3fd5e79f7
UPDATE usuarios 
SET password_hash = 'pbkdf2:sha256:600000$4VfADb7eOdJ5gQ2W$58bf51cb43f4979f06d8d1f873c2197bc394c037b4ce851bd370c1d3fd5e79f7',
    rol = 'admin'
WHERE username = 'admin';

-- Opción 3: Eliminar usuarios con password_hash inválido (¡CUIDADO! Solo si es necesario)
-- DELETE FROM usuarios WHERE password_hash IS NULL OR password_hash = '' OR password_hash NOT LIKE 'pbkdf2:%';

