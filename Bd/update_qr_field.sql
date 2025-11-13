-- Script para actualizar la tabla estudiantes existente
-- Ejecutar este script si la tabla ya existe y necesita agregar el campo qr_code

USE asistencia_db;

-- Agregar columna qr_code si no existe
ALTER TABLE estudiantes 
ADD COLUMN IF NOT EXISTS qr_code TEXT AFTER correo;

-- Si tu versión de MySQL no soporta IF NOT EXISTS, usar:
-- ALTER TABLE estudiantes ADD COLUMN qr_code TEXT AFTER correo;

