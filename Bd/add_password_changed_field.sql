-- Script para agregar el campo password_changed a la tabla usuarios
-- Este campo rastrea si un alumno ya cambió su contraseña inicial

-- Agregar columna password_changed si no existe
ALTER TABLE usuarios
ADD COLUMN IF NOT EXISTS password_changed BOOLEAN DEFAULT FALSE;

-- Actualizar todos los usuarios existentes (excepto alumnos nuevos) para que tengan password_changed = TRUE
-- Esto es para usuarios que ya existían antes de esta actualización
UPDATE usuarios
SET password_changed = TRUE
WHERE password_changed IS NULL OR password_changed = FALSE;

-- Crear índice para mejorar consultas
CREATE INDEX IF NOT EXISTS idx_usuarios_password_changed ON usuarios(password_changed);

