CREATE DATABASE IF NOT EXISTS asistencia_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE asistencia_db;

-- Tabla de usuarios (maestros)
CREATE TABLE usuarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(80) NOT NULL UNIQUE,
  email VARCHAR(120) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  nombre_completo VARCHAR(150) NOT NULL,
  activo BOOLEAN DEFAULT TRUE,
  creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
select * from usuarios;

CREATE TABLE estudiantes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  numero_control VARCHAR(50) NOT NULL UNIQUE,
  nombre VARCHAR(150) NOT NULL,
  correo VARCHAR(150),
  qr_code TEXT,
  creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE clases (
  id INT AUTO_INCREMENT PRIMARY KEY,
  codigo_clase VARCHAR(50) NOT NULL,
  nombre_clase VARCHAR(150) NOT NULL,
  usuario_id INT NOT NULL,
  creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
  UNIQUE KEY unique_codigo_usuario (codigo_clase, usuario_id)
);


select * from estudiantes;
select * from usuarios;

-- Tabla de asociación muchos a muchos entre Estudiante y Clase
CREATE TABLE estudiante_clase (
  estudiante_id INT NOT NULL,
  clase_id INT NOT NULL,
  asignado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (estudiante_id, clase_id),
  FOREIGN KEY (estudiante_id) REFERENCES estudiantes(id) ON DELETE CASCADE,
  FOREIGN KEY (clase_id) REFERENCES clases(id) ON DELETE CASCADE
);

CREATE TABLE asistencias (
  id INT AUTO_INCREMENT PRIMARY KEY,
  estudiante_id INT NOT NULL,
  clase_id INT NOT NULL,
  fecha DATE NOT NULL,
  hora TIME NOT NULL,
  metodo VARCHAR(50) DEFAULT 'QR',
  info_extra JSON,
  creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (estudiante_id) REFERENCES estudiantes(id) ON DELETE CASCADE,
  FOREIGN KEY (clase_id) REFERENCES clases(id) ON DELETE CASCADE,
  UNIQUE KEY unica_asistencia_por_dia (estudiante_id, clase_id, fecha)
);

-- Agregar campo 'rol' a la tabla 'usuarios' si no existe
-- Agregar columna 'rol' a la tabla 'usuarios' (solo ejecutar una vez)
ALTER TABLE usuarios 
ADD COLUMN rol VARCHAR(20) NOT NULL DEFAULT 'profesor';

-- Actualizar los usuarios existentes sin rol
SET SQL_SAFE_UPDATES = 0;

UPDATE usuarios 
SET rol = 'profesor' 
WHERE rol IS NULL OR rol = '';

SET SQL_SAFE_UPDATES = 1;


-- Agregar columna 'usuario_id' a la tabla 'estudiantes'
ALTER TABLE estudiantes 
ADD COLUMN usuario_id INT NULL;

-- Crear la relación foránea
ALTER TABLE estudiantes 
ADD CONSTRAINT fk_estudiante_usuario 
FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL;

-- Crear índices para mejorar rendimiento
CREATE INDEX idx_estudiantes_usuario_id ON estudiantes(usuario_id);
CREATE INDEX idx_usuarios_rol ON usuarios(rol);



-- ================================================
-- Script para crear un usuario administrador
-- ================================================

INSERT INTO usuarios (username, email, password_hash, nombre_completo, rol, activo, creado_en)
VALUES (
    'admin',
    'admin@tectijuana.edu.mx',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyY5Y5Y5Y5Y5Y',  -- Reemplazar con hash real
    'Administrador del Sistema',
    'admin',
    1,
    NOW()
);


-- UPDATE usuarios SET rol = 'admin' WHERE username = 'nombre_usuario';


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

select * from usuarios;

SET SQL_SAFE_UPDATES = 0;

UPDATE usuarios
SET rol = 'admin'
WHERE username = 'Cesar05';

SET SQL_SAFE_UPDATES = 1;



-- 🔹 1. Verificar y agregar la columna 'password_changed' solo si no existe
SET @columna_existe := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_NAME = 'usuarios'
    AND COLUMN_NAME = 'password_changed'
    AND TABLE_SCHEMA = DATABASE()
);

SET @sql := IF(
  @columna_existe = 0,
  'ALTER TABLE usuarios ADD COLUMN password_changed BOOLEAN DEFAULT FALSE;',
  'SELECT "La columna password_changed ya existe" AS mensaje;'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;


-- 🔹 2. Actualizar todos los usuarios existentes (excepto alumnos nuevos)
SET SQL_SAFE_UPDATES = 0;

UPDATE usuarios
SET password_changed = TRUE
WHERE password_changed IS NULL OR password_changed = FALSE;

SET SQL_SAFE_UPDATES = 1;


-- 🔹 3. Crear el índice solo si no existe
SET @index_existe := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'usuarios'
    AND INDEX_NAME = 'idx_usuarios_password_changed'
);

SET @sql_index := IF(
  @index_existe = 0,
  'CREATE INDEX idx_usuarios_password_changed ON usuarios(password_changed);',
  'SELECT "El índice idx_usuarios_password_changed ya existe" AS mensaje;'
);
PREPARE stmt_index FROM @sql_index;
EXECUTE stmt_index;
DEALLOCATE PREPARE stmt_index;


-- ================================================
-- Script para crear tabla de horarios de clases
-- ================================================

-- Crear tabla de horarios de clases
CREATE TABLE IF NOT EXISTS horarios_clase (
  id INT AUTO_INCREMENT PRIMARY KEY,
  clase_id INT NOT NULL,
  dia_semana TINYINT NOT NULL COMMENT '1=Lunes, 2=Martes, 3=Miércoles, 4=Jueves, 5=Viernes',
  hora_inicio TIME NOT NULL,
  hora_fin TIME NOT NULL,
  creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (clase_id) REFERENCES clases(id) ON DELETE CASCADE,
  UNIQUE KEY unique_clase_dia (clase_id, dia_semana),
  INDEX idx_clase_id (clase_id),
  INDEX idx_dia_semana (dia_semana),
  CHECK (dia_semana BETWEEN 1 AND 5),
  CHECK (hora_fin > hora_inicio)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Verificar que la tabla se creó correctamente
SELECT 'Tabla horarios_clase creada exitosamente' AS mensaje;


select * from usuarios;

-- ================================================
-- Script para crear tabla de reportes enviados
-- ================================================

-- Crear tabla para rastrear reportes enviados por correo
CREATE TABLE IF NOT EXISTS reportes_enviados (
  id INT AUTO_INCREMENT PRIMARY KEY,
  clase_id INT NOT NULL,
  fecha_clase DATE NOT NULL,
  enviado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (clase_id) REFERENCES clases(id) ON DELETE CASCADE,
  UNIQUE KEY unique_reporte_dia (clase_id, fecha_clase),
  INDEX idx_clase_id (clase_id),
  INDEX idx_fecha_clase (fecha_clase)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Verificar que la tabla se creó correctamente
SELECT 'Tabla reportes_enviados creada exitosamente' AS mensaje;

