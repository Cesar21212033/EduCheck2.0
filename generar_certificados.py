"""
Script para generar certificados SSL autofirmados para desarrollo
Estos certificados permiten usar HTTPS en desarrollo local
"""
import os
import subprocess
import sys

def generar_certificados():
    """Genera certificados SSL autofirmados para desarrollo"""
    
    # Crear directorio para certificados si no existe
    cert_dir = os.path.join(os.path.dirname(__file__), 'certificados')
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
    
    cert_file = os.path.join(cert_dir, 'cert.pem')
    key_file = os.path.join(cert_dir, 'key.pem')
    
    # Verificar si ya existen
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("[OK] Los certificados ya existen en:", cert_dir)
        print(f"  Certificado: {cert_file}")
        print(f"  Clave: {key_file}")
        return cert_file, key_file
    
    print("Generando certificados SSL autofirmados...")
    print("Esto puede tomar unos segundos...")
    
    try:
        # Generar certificado autofirmado usando OpenSSL
        # Obtener la IP local para el certificado
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Comando para generar certificado
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-nodes', '-out', cert_file,
            '-keyout', key_file,
            '-days', '365',
            '-subj', f'/CN={local_ip}/O=EduCheck/C=MX'
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
        
        print("[OK] Certificados generados exitosamente!")
        print(f"  Certificado: {cert_file}")
        print(f"  Clave: {key_file}")
        print("\n[!] NOTA: Estos son certificados autofirmados para desarrollo.")
        print("   Tu navegador mostrara una advertencia de seguridad.")
        print("   En iPhone, necesitaras aceptar el certificado manualmente.")
        
        return cert_file, key_file
        
    except FileNotFoundError:
        print("\n[!] Error: OpenSSL no esta instalado.")
        print("\nPara instalar OpenSSL:")
        print("  Windows: Descarga desde https://slproweb.com/products/Win32OpenSSL.html")
        print("  O usa Git Bash que incluye OpenSSL")
        print("\nAlternativa: Usa el metodo manual con pyOpenSSL (mas abajo)")
        return None, None
    except subprocess.CalledProcessError as e:
        print(f"\n[!] Error al generar certificados: {e}")
        return None, None

def generar_con_pyopenssl():
    """Genera certificados usando pyOpenSSL (alternativa)"""
    try:
        from OpenSSL import crypto
        
        cert_dir = os.path.join(os.path.dirname(__file__), 'certificados')
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        
        cert_file = os.path.join(cert_dir, 'cert.pem')
        key_file = os.path.join(cert_dir, 'key.pem')
        
        # Obtener IP local
        import socket
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except:
            local_ip = "127.0.0.1"
        
        print(f"Generando certificado para: localhost, 127.0.0.1, {local_ip}")
        
        # Crear clave privada
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        # Crear certificado
        cert = crypto.X509()
        cert.get_subject().CN = "localhost"
        cert.get_subject().O = "EduCheck"
        cert.get_subject().C = "MX"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)  # 1 año
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        
        # Agregar Subject Alternative Names (SAN) para incluir IPs
        # Esto permite que el certificado funcione con IPs además de localhost
        san_list = [
            'DNS:localhost',
            'DNS:127.0.0.1',
            'IP:127.0.0.1',
            f'IP:{local_ip}',
            f'DNS:{local_ip}'
        ]
        
        # Agregar extensiones SAN
        from OpenSSL import SSL
        cert.add_extensions([
            crypto.X509Extension(
                b"subjectAltName",
                False,
                ", ".join(san_list).encode()
            )
        ])
        
        cert.sign(key, 'sha256')
        
        # Guardar certificado
        with open(cert_file, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        # Guardar clave
        with open(key_file, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        print("[OK] Certificados generados con pyOpenSSL!")
        print(f"  Certificado: {cert_file}")
        print(f"  Clave: {key_file}")
        print(f"  Valido para: localhost, 127.0.0.1, {local_ip}")
        
        return cert_file, key_file
        
    except ImportError:
        print("\n[!] pyOpenSSL no esta instalado.")
        print("Instala con: pip install pyopenssl")
        return None, None
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return None, None

if __name__ == '__main__':
    print("=" * 60)
    print("Generador de Certificados SSL para EduCheck")
    print("=" * 60)
    print()
    
    # Intentar primero con pyOpenSSL (más confiable en Windows)
    print("Intentando generar certificados con pyOpenSSL...")
    cert, key = generar_con_pyopenssl()
    
    if not cert or not key:
        print("\nIntentando metodo alternativo con OpenSSL...")
        cert, key = generar_certificados()
    
    if cert and key:
        print("\n" + "=" * 60)
        print("[OK] Certificados listos!")
        print("=" * 60)
        print("\nAhora puedes ejecutar Flask con HTTPS:")
        print("  python app.py")
        print("\nO con flask run:")
        print("  flask run --host=0.0.0.0 --port=5000 --cert=certificados/cert.pem --key=certificados/key.pem")
    else:
        print("\n" + "=" * 60)
        print("[!] No se pudieron generar los certificados")
        print("=" * 60)
        print("\nOpciones:")
        print("1. Instala OpenSSL y vuelve a ejecutar este script")
        print("2. Instala pyOpenSSL: pip install pyopenssl")
        print("3. Usa ngrok para crear un tunel HTTPS (ver CONFIGURACION_HTTPS.md)")

