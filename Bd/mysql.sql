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
