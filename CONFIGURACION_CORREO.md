# Configuración de Correo Electrónico

Para que el sistema pueda enviar los códigos QR por correo electrónico, necesitas configurar las siguientes variables de entorno en tu archivo `.env`:

## Variables Requeridas

```env
MAIL_SERVER=smtp.office365.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=l21212033@tectijuana.edu.mx
MAIL_PASSWORD=tu-contraseña
MAIL_DEFAULT_SENDER=l21212033@tectijuana.edu.mx
```

**Nota:** El sistema está configurado para enviar correos desde `l21212033@tectijuana.edu.mx` y acepta correos con terminación `@tectijuana.edu.mx`.

## Configuración para TEC Tijuana (Office 365)

El sistema está configurado para usar Office 365 de TEC Tijuana:

1. **Usa tu cuenta institucional**: `l21212033@tectijuana.edu.mx`
2. **Contraseña**: Usa tu contraseña de Office 365
3. **Servidor SMTP**: `smtp.office365.com`
4. **Puerto**: `587` con TLS habilitado

### Configuración para Gmail (alternativa)

Si prefieres usar Gmail, necesitas:

1. **Habilitar la verificación en dos pasos** en tu cuenta de Google
2. **Generar una "Contraseña de aplicación"**:
   - Ve a: https://myaccount.google.com/apppasswords
   - Selecciona "Correo" y "Otro (nombre personalizado)"
   - Ingresa "EduCheck" como nombre
   - Copia la contraseña generada (16 caracteres)
   - Usa esta contraseña en `MAIL_PASSWORD`
   
   Y cambia en `.env`:
   ```env
   MAIL_SERVER=smtp.gmail.com
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
- Otros correos electrónicos válidos con formato estándar

## Notas

- El correo electrónico del estudiante ahora es **obligatorio** al registrarse
- El QR se envía automáticamente al correo del estudiante después del registro
- Todos los correos se envían desde `l21212033@tectijuana.edu.mx`
- Si hay un error al enviar el correo, el estudiante se registra igualmente, pero se muestra una advertencia

