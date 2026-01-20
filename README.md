# Sentinel-Mail Engine v1.0.0 (Enterprise Edition)

## 📋 Descripción
Motor de notificaciones avanzado diseñado para la plataforma **SIEM Wazuh**. Este sistema transforma logs técnicos complejos en reportes ejecutivos y forenses visuales en formato HTML, optimizando drásticamente el **Mean Time To Respond (MTTR)** en entornos SOC.

## 🚀 Características Principales

* **Universal Evidence Tracker:** Algoritmo de búsqueda jerárquica que captura logs en infraestructuras híbridas, extrayendo datos de `full_log` (Linux) y de las estructuras profundas de `EventData` (Windows).

* **Flood Control Atómico:** Mecanismo basado en persistencia de estado para prevenir la saturación del servidor de correo durante tormentas de alertas (máximo 10 alertas/min).

* **Security Hardening:** Implementa sanitización de datos (Anti-XSS) mediante `html.escape()` y gestión de concurrencia mediante **File Locking** con la librería `fcntl`.

* **Arquitectura Modular:** Separación estricta entre la lógica de procesamiento y los parámetros de red mediante configuración externa en JSON.

## 🧠 Detalles Técnicos y Flujo de Lógica

### 1. Motor de Extracción Forense (Universal Evidence Tracker)

El script implementa una lógica de "búsqueda en cascada" para garantizar que la evidencia nunca llegue vacía al analista:

1. **Prioridad Unix:** Extrae datos del campo `full_log`.

2. **Prioridad Windows:** Deserializa estructuras complejas de `win.eventdata.message` o `win.system.message`.

3. **Fallback:** Captura descripciones genéricas si no hay datos forenses específicos disponibles.

### 2. Algoritmo de Control de Inundación (Flood Control)

Para proteger la disponibilidad del servicio de mensajería:

* Utiliza un archivo de estado atómico (`sentinel_mail_state.json`) para rastrear el tiempo y conteo de alertas.

* Aplica `fcntl.flock` para evitar condiciones de carrera (*Race Conditions*) cuando ocurren alertas simultáneas.


### 3. Sanitización y Seguridad (Hardening)

* **Protección del Analista:** Todo dato proveniente del agente es sanitizado para prevenir ataques de **Stored XSS** en la bandeja de entrada.

* **Principio de Menor Privilegio:** Diseñado para ejecutarse bajo el contexto del usuario `wazuh` con acceso restringido a archivos de configuración sensibles.

## 🛠️ Configuración e Implementación

El motor requiere un archivo de configuración externo para mantener la seguridad de las credenciales:

**Ruta:** `/var/ossec/etc/integrations/sentinel_config.json`

```json
{
  "smtp_server": "smtp.tuservidor.com",
  "smtp_port": 587,
  "email_from": "alertas-siem@tuempresa.com",
  "recipients": ["analista-soc@tuempresa.com"],
  "dashboard_url": "[https://tu-siem-dashboard.com](https://tu-siem-dashboard.com)"
}
Permisos Recomendados (Best Practices)

Bash
# Permisos para el motor de ejecución

chown root:wazuh /var/ossec/integrations/sentinel-mail

chmod 750 /var/ossec/integrations/sentinel-mail

# Permisos para el archivo de configuración con credenciales

chown root:wazuh /var/ossec/etc/integrations/sentinel_config.json

chmod 660 /var/ossec/etc/integrations/sentinel_config.json

# Ver el log de auditoría del motor de notificaciones

tail -f /var/ossec/logs/integrations.log

Interpretación de eventos en el log:

sentinel-mail: Enviado: ...: El correo ha sido entregado exitosamente al servidor de salida.

ERROR: No existe el archivo...: Verifique que el JSON de configuración esté en la ruta /var/ossec/etc/integrations/.

Error SMTP: ...: Problemas de comunicación con el servidor de correo o credenciales incorrectas.

DEBUG: Flood control active...: Indica que el motor bloqueó un envío para prevenir saturación (comportamiento esperado bajo carga).

Desarrollado por: Emanuel Carreño Rol: Especialista en Monitoreo de Seguridad Proyecto: Sentinel-Mail Engine para Wazuh SIEM