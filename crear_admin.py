"""
Script para crear un usuario administrador
Ejecutar: python crear_admin.py
"""
from app import app, db, Usuario
from werkzeug.security import generate_password_hash

def crear_admin():
    with app.app_context():
        # Verificar si ya existe un admin
        admin_existente = Usuario.query.filter_by(rol='admin').first()
        if admin_existente:
            print(f"Ya existe un usuario admin: {admin_existente.username}")
            respuesta = input("¿Deseas crear otro admin? (s/n): ")
            if respuesta.lower() != 's':
                return
        
        # Solicitar datos
        print("\n=== Crear Usuario Administrador ===")
        username = input("Nombre de usuario: ").strip()
        
        # Verificar si el username ya existe
        if Usuario.query.filter_by(username=username).first():
            print(f"Error: El usuario '{username}' ya existe.")
            return
        
        email = input("Correo electrónico: ").strip()
        
        # Verificar si el email ya existe
        if Usuario.query.filter_by(email=email).first():
            print(f"Error: El correo '{email}' ya está registrado.")
            return
        
        nombre_completo = input("Nombre completo: ").strip()
        password = input("Contraseña: ").strip()
        password_confirm = input("Confirmar contraseña: ").strip()
        
        if password != password_confirm:
            print("Error: Las contraseñas no coinciden.")
            return
        
        if len(password) < 6:
            print("Error: La contraseña debe tener al menos 6 caracteres.")
            return
        
        # Crear usuario admin
        nuevo_admin = Usuario(
            username=username,
            email=email,
            nombre_completo=nombre_completo,
            rol='admin'
        )
        nuevo_admin.set_password(password)
        
        try:
            db.session.add(nuevo_admin)
            db.session.commit()
            print(f"\n✓ Usuario administrador '{username}' creado exitosamente!")
            print(f"  Email: {email}")
            print(f"  Nombre: {nombre_completo}")
            print(f"\nPuedes iniciar sesión con:")
            print(f"  Usuario: {username}")
            print(f"  Contraseña: (la que ingresaste)")
        except Exception as e:
            db.session.rollback()
            print(f"Error al crear usuario: {str(e)}")

if __name__ == '__main__':
    crear_admin()

