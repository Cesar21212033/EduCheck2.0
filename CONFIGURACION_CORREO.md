# Configuración de Correo Electrónico

Para que el sistema pueda enviar los códigos QR por correo electrónico, necesitas configurar las siguientes variables de entorno en tu archivo `c.env` (o `.env`):

## Variables Requeridas

```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=cesarini.05ramos@gmail.com
MAIL_PASSWORD=tu-contraseña-de-aplicación
MAIL_DEFAULT_SENDER=cesarini.05ramos@gmail.com
```

**Nota:** El sistema está configurado para enviar correos desde `cesarini.05ramos@gmail.com`.

## Configuración para Gmail

**⚠️ IMPORTANTE:** Gmail requiere una **"Contraseña de aplicación"** en lugar de tu contraseña normal. La contraseña de tu cuenta no funcionará directamente con aplicaciones de terceros.

### Pasos para configurar Gmail:

1. **Habilita la verificación en dos pasos** en tu cuenta de Google:
   - Ve a: https://myaccount.google.com/security
   - Busca "Verificación en dos pasos" y actívala si no está habilitada
   - Sigue las instrucciones para configurarla (puede requerir un número de teléfono)

2. **Genera una Contraseña de aplicación**:
   - Ve a: https://myaccount.google.com/apppasswords
   - Si no aparece directamente, ve a "Seguridad" → "Contraseñas de aplicaciones"
   - Selecciona "Correo" como aplicación
   - Selecciona "Otro (nombre personalizado)" como dispositivo
   - Ingresa un nombre descriptivo (ej: "EduCheck Sistema")
   - Haz clic en "Generar"
   - **Copia la contraseña generada** (16 caracteres, sin espacios)
   - **Úsala en `MAIL_PASSWORD`** en lugar de tu contraseña normal

3. **Configuración en `c.env`**:
   ```env
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USERNAME=cesarini.05ramos@gmail.com
   MAIL_PASSWORD=la-contraseña-de-aplicación-generada-de-16-caracteres
   MAIL_DEFAULT_SENDER=cesarini.05ramos@gmail.com
   ```

**Ejemplo de contraseña de aplicación:** `abcd efgh ijkl mnop` (sin espacios: `abcdefghijklmnop`)

### Notas importantes sobre Gmail:

- La contraseña de aplicación es diferente a tu contraseña de Gmail
- Cada contraseña de aplicación es única y solo funciona para la aplicación para la que fue creada
- Puedes generar múltiples contraseñas de aplicación para diferentes aplicaciones
- Si cambias tu contraseña de Gmail, las contraseñas de aplicación siguen funcionando
- Puedes revocar una contraseña de aplicación en cualquier momento desde la configuración de seguridad

## Configuración Alternativa: Office 365

Si prefieres usar Office 365 (por ejemplo, `@tectijuana.edu.mx`), necesitas:

1. **Habilita la verificación en dos pasos** en tu cuenta de Microsoft
2. **Genera una Contraseña de aplicación**:
   - Ve a: https://account.microsoft.com/security
   - Busca "Contraseñas de aplicación" o "App passwords"
   - Genera una nueva contraseña de aplicación
   - Úsala en `MAIL_PASSWORD`

3. **Configuración en `c.env`**:
   ```env
   MAIL_SERVER=smtp.office365.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USERNAME=tu-email@tectijuana.edu.mx
   MAIL_PASSWORD=la-contraseña-de-aplicación-generada
   MAIL_DEFAULT_SENDER=tu-email@tectijuana.edu.mx
   ```

## Otros Proveedores de Correo

### Outlook/Hotmail
```env
MAIL_SERVER=smtp-mail.outlook.com
MAIL_PORT=587
MAIL_USE_TLS=True
```

### Yahoo
```env
MAIL_SERVER=smtp.mail.yahoo.com
MAIL_PORT=587
MAIL_USE_TLS=True
```

## Instalación de Dependencias

Asegúrate de instalar Flask-Mail:

```bash
pip install Flask-Mail==0.9.1
```

O instala todas las dependencias:

```bash
pip install -r requirements.txt
```

## Validación de Correos

El sistema acepta:
- Correos con terminación `@tectijuana.edu.mx` (dominio institucional)
- Otros correos electrónicos válidos con formato estándar (Gmail, Outlook, Yahoo, etc.)

## Notas Importantes

- El correo electrónico del estudiante es **obligatorio** al registrarse
- El QR se envía automáticamente al correo del estudiante después del registro
- Todos los correos se envían desde `cesarini.05ramos@gmail.com`
- Si hay un error al enviar el correo, el estudiante se registra igualmente, pero se muestra una advertencia
- El QR siempre se guarda en la base de datos, incluso si falla el envío del correo
- Después de actualizar `MAIL_PASSWORD`, **reinicia el servidor Flask** para que los cambios surtan efecto

## Solución de Problemas

### Error: "Error de autenticación"
- Verifica que estés usando una **contraseña de aplicación**, no tu contraseña normal
- Asegúrate de que la verificación en dos pasos esté habilitada
- Verifica que no haya espacios en la contraseña de aplicación en `c.env`

### Error: "Error de conexión"
- Verifica tu conexión a internet
- Verifica que `MAIL_SERVER` y `MAIL_PORT` sean correctos
- Para Gmail, asegúrate de usar `smtp.gmail.com` y puerto `587`

### Error: "Configuración de correo incompleta"
- Verifica que todas las variables estén configuradas en `c.env`
- Asegúrate de que el archivo `c.env` esté en el mismo directorio que `app.py`
- Reinicia el servidor Flask después de modificar `c.env`
