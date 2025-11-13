-- Script para actualizar la base de datos existente con las nuevas tablas de autenticación
-- Ejecutar este script si la base de datos ya existe

USE asistencia_db;

-- Agregar tabla de usuarios si no existe
CREATE TABLE IF NOT EXISTS usuarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(80) NOT NULL UNIQUE,
  email VARCHAR(120) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  nombre_completo VARCHAR(150) NOT NULL,
  activo BOOLEAN DEFAULT TRUE,
  creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agregar columna usuario_id a clases si no existe
ALTER TABLE clases 
ADD COLUMN IF NOT EXISTS usuario_id INT AFTER nombre_clase;

-- Si tu versión de MySQL no soporta IF NOT EXISTS, usar:
-- ALTER TABLE clases ADD COLUMN usuario_id INT AFTER nombre_clase;

-- Agregar foreign key si no existe
-- Primero eliminar la restricción unique de codigo_clase si existe
ALTER TABLE clases DROP INDEX IF EXISTS codigo_clase;

-- Agregar nueva restricción unique para codigo_clase y usuario_id
ALTER TABLE clases 
ADD UNIQUE KEY IF NOT EXISTS unique_codigo_usuario (codigo_clase, usuario_id);

-- Agregar foreign key
ALTER TABLE clases 
ADD CONSTRAINT IF NOT EXISTS fk_clase_usuario 
FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE;

-- Crear tabla de asociación estudiante_clase si no existe
CREATE TABLE IF NOT EXISTS estudiante_clase (
  estudiante_id INT NOT NULL,
  clase_id INT NOT NULL,
  asignado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (estudiante_id, clase_id),
  FOREIGN KEY (estudiante_id) REFERENCES estudiantes(id) ON DELETE CASCADE,
  FOREIGN KEY (clase_id) REFERENCES clases(id) ON DELETE CASCADE
);

-- NOTA: Si ya tienes clases creadas, necesitarás asignar un usuario_id a cada clase
-- Puedes hacerlo manualmente o crear un usuario por defecto y asignarlo

