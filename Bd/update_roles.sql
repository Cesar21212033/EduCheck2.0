-- Script para agregar campo de rol y usuario_id a estudiantes
-- Ejecutar este script en la base de datos para actualizar el esquema

-- Agregar campo rol a la tabla usuarios (si no existe)
ALTER TABLE usuarios 
ADD COLUMN IF NOT EXISTS rol VARCHAR(20) NOT NULL DEFAULT 'profesor';

-- Actualizar usuarios existentes sin rol a 'profesor'
UPDATE usuarios SET rol = 'profesor' WHERE rol IS NULL OR rol = '';

-- Agregar campo usuario_id a la tabla estudiantes (si no existe)
ALTER TABLE estudiantes 
ADD COLUMN IF NOT EXISTS usuario_id INT NULL,
ADD CONSTRAINT fk_estudiante_usuario 
FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL;

-- Crear índice para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_estudiantes_usuario_id ON estudiantes(usuario_id);
CREATE INDEX IF NOT EXISTS idx_usuarios_rol ON usuarios(rol);

-- Nota: Los usuarios tipo 'admin' deben crearse manualmente o mediante el sistema
-- Ejemplo para crear un admin:
-- UPDATE usuarios SET rol = 'admin' WHERE username = 'admin';

