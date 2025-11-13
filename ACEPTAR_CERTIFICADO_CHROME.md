# Cómo aceptar el certificado SSL en Chrome

## ¿Por qué aparece esta advertencia?

Chrome muestra "La conexión no es privada" porque el certificado SSL es **autofirmado** (no está firmado por una autoridad certificadora reconocida). Esto es **normal y seguro** para desarrollo local.

## Pasos para aceptar el certificado en Chrome

### Método 1: Aceptar directamente (más rápido)

1. Cuando veas la advertencia "La conexión no es privada", haz clic en **"Avanzado"** o **"Advanced"**
2. Verás un mensaje que dice algo como: "El certificado del servidor no es válido"
3. Haz clic en **"Continuar a localhost (no seguro)"** o **"Proceed to localhost (unsafe)"**
4. Chrome guardará tu elección y ya no mostrará la advertencia para ese sitio

### Método 2: Confiar en el certificado permanentemente (recomendado)

1. Cuando veas la advertencia, haz clic en **"Avanzado"**
2. Haz clic en **"Continuar a localhost (no seguro)"** la primera vez
3. Una vez dentro del sitio, haz clic en el **candado** en la barra de direcciones
4. Haz clic en **"Certificado"** o **"Certificate"**
5. En la ventana del certificado, haz clic en **"Instalar certificado"** o **"Install Certificate"**
6. Selecciona **"Almacén de certificados"** o **"Certificate Store"**
7. Elige **"Confiar en las personas"** o **"Trusted People"**
8. Sigue las instrucciones para completar la instalación

### Método 3: Usar la bandera de Chrome (solo para desarrollo)

**⚠️ ADVERTENCIA: Solo para desarrollo local. No uses esto en producción.**

1. Cierra Chrome completamente
2. Abre Chrome con esta bandera:
   ```bash
   chrome.exe --ignore-certificate-errors --ignore-ssl-errors --user-data-dir="C:\temp\chrome_dev"
   ```
   O en PowerShell:
   ```powershell
   & "C:\Program Files\Google\Chrome\Application\chrome.exe" --ignore-certificate-errors --ignore-ssl-errors --user-data-dir="C:\temp\chrome_dev"
   ```

## ¿Es seguro?

**Sí, es seguro para desarrollo local** porque:
- Estás accediendo a `localhost` (tu propia computadora)
- El certificado es autofirmado por ti mismo
- No hay riesgo de que alguien intercepte tu conexión local

**NO es seguro** si:
- Estás accediendo desde una red pública
- El sitio no es realmente localhost
- Estás en producción

## Alternativa: Usar HTTP solo en localhost

Si prefieres evitar HTTPS completamente en desarrollo local, puedes modificar `app.py` para usar HTTP solo en localhost. Sin embargo, **esto no funcionará en iPhone** porque iOS requiere HTTPS para acceder a la cámara.

## Solución rápida

**La forma más rápida:** Simplemente haz clic en "Avanzado" > "Continuar a localhost (no seguro)" cada vez que veas la advertencia. Chrome recordará tu elección.

