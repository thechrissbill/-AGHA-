import os
import json
import datetime
import argparse

# Propuesta de mapa de recomendaciones
RECOMMENDATION_MAP = {
    "xss": "Para mitigar las vulnerabilidades de Cross-Site Scripting (XSS), asegúrese de que todas las entradas del usuario sean validadas y sanitizadas. Implemente una codificación de salida contextual robusta antes de renderizar datos en la página. Considere el uso de una Política de Seguridad de Contenido (CSP) para restringir la ejecución de scripts.",
    "sqli": "Para prevenir la Inyección SQL (SQLi), utilice siempre consultas parametrizadas (sentencias preparadas) en lugar de construir consultas SQL concatenando cadenas. Aplique el principio de mínimo privilegio a las cuentas de la base de datos.",
    "rce": "Las vulnerabilidades de Ejecución Remota de Código (RCE) son críticas. Asegure que todas las entradas de usuario sean estrictamente validadas y que no se ejecuten comandos del sistema con datos no confiables. Implemente el principio de mínimo privilegio en los procesos de la aplicación.",
    "lfi": "Para prevenir la Inclusión de Archivos Locales (LFI), evite el uso de entradas de usuario directamente en rutas de archivos. Utilice listas blancas para los nombres de archivo permitidos y asegúrese de que los archivos incluidos estén dentro de un directorio seguro y predefinido.",
    "info-disclosure": "La divulgación de información sensible puede llevar a ataques posteriores. Asegúrese de que los mensajes de error no revelen detalles internos del sistema, que los archivos de configuración y logs no sean accesibles públicamente, y que los directorios no tengan listado habilitado.",
    "misconfig": "Las configuraciones incorrectas son una fuente común de vulnerabilidades. Revise y aplique las guías de hardening de seguridad para todos los componentes de su infraestructura (servidores web, bases de datos, sistemas operativos). Deshabilite funcionalidades innecesarias y cambie las credenciales por defecto.",
    "cve": "Para las vulnerabilidades de CVE (Common Vulnerabilities and Exposures), es crucial mantener todo el software actualizado con los últimos parches de seguridad. Implemente un programa de gestión de parches y monitoree activamente las bases de datos de CVEs relevantes para sus tecnologías.",
    "panel": "Los paneles de administración expuestos son un riesgo significativo. Restrinja el acceso a estos paneles mediante listas blancas de IP, VPNs, autenticación multifactor (MFA) y contraseñas fuertes y únicas. Monitoree los intentos de acceso fallidos.",
    "xxe": "Para prevenir la Inyección XML External Entity (XXE), configure los parsers XML para deshabilitar la resolución de entidades externas y el procesamiento de DTDs externas. Valide y sanee todas las entradas XML.",
    "ssrf": "Para mitigar las vulnerabilidades de Server-Side Request Forgery (SSRF), valide estrictamente las URLs proporcionadas por el usuario. Utilice listas blancas de dominios y protocolos permitidos. Considere el uso de un proxy interno para filtrar y controlar las solicitudes salientes.",
    "open-redirect": "Para prevenir redirecciones abiertas, evite construir URLs de redirección directamente a partir de entradas de usuario. Si es necesario, utilice una lista blanca de dominios permitidos para las redirecciones o implemente un token de validación.",
    "takeover": "Las vulnerabilidades de Subdomain Takeover ocurren cuando un subdominio apunta a un servicio inactivo. Revise regularmente los registros DNS y elimine las entradas que apunten a servicios que ya no están en uso o que han sido desaprovisionados.",
    "default": "Se ha detectado un hallazgo que requiere atención. Revise la descripción específica de la vulnerabilidad y consulte las mejores prácticas de seguridad para la tecnología o el tipo de vulnerabilidad identificado. Mantenga el software actualizado y siga los principios de seguridad por diseño."
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_report(workspace_path):
    """Lee todos los archivos JSONL en el workspace y genera un informe consolidado."""
    print(f"[*] Iniciando generación de informe para el workspace: {workspace_path}")
    all_findings = []

    # 1. Recopilar todos los hallazgos
    for filename in sorted(os.listdir(workspace_path)):
        if filename.endswith(".json"):
            filepath = os.path.join(workspace_path, filename)
            with open(filepath, 'r') as f:
                for line in f:
                    try:
                        all_findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    
    if not all_findings:
        print("[-] No se encontraron hallazgos en el workspace. No se generará el informe.")
        return

    # 2. Eliminar duplicados y ordenar
    unique_findings = {}
    for finding in all_findings:
        unique_key = (finding.get('host'), finding.get('template-id'), finding.get('matched-at'))
        unique_findings[unique_key] = finding

    # Mapeo de severidad para una ordenación lógica
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    sorted_findings = sorted(unique_findings.values(), key=lambda x: severity_order.get(x.get('info', {}).get('severity', 'unknown'), 99))

    # 3. Generar los archivos de informe
    report_md_path = os.path.join(workspace_path, "_Hunter_Report.md")
    report_raw_path = os.path.join(workspace_path, "_Full_Raw_Output.txt")

    with open(report_md_path, 'w') as md_f, open(report_raw_path, 'w') as raw_f:
        target = sorted_findings[0].get('host', 'N/A')
        report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        md_f.write(f"# Informe de Auditoría de Seguridad - AGHA\n\n")
        md_f.write(f"**Objetivo:** `{target}`\n")
        md_f.write(f"**Fecha de Generación:** {report_date}\n\n")
        md_f.write("Este informe fue generado por el pipeline reactivo de AGHA. Las vulnerabilidades se listan en orden de severidad.\n\n")
        md_f.write("---\n\n")

        # --- Resumen Ejecutivo ---
        md_f.write("## Resumen Ejecutivo\n\n")
        total_findings = len(sorted_findings)
        critical_count = sum(1 for f in sorted_findings if f.get('info', {}).get('severity') == 'critical')
        high_count = sum(1 for f in sorted_findings if f.get('info', {}).get('severity') == 'high')

        if critical_count > 0 or high_count > 0:
            md_f.write(f"Se identificaron **{total_findings}** hallazgos de seguridad. De estos, **{critical_count}** son de severidad CRÍTICA y **{high_count}** son de severidad ALTA. Estos hallazgos representan riesgos significativos que requieren atención inmediata para proteger la integridad y confidencialidad de los activos.\n\n")
        elif total_findings > 0:
            md_f.write(f"Se identificaron **{total_findings}** hallazgos de seguridad, principalmente de severidad media y baja. Aunque no representan un riesgo crítico inmediato, su remediación es importante para mejorar la postura de seguridad general y prevenir posibles escaladas de privilegios.\n\n")
        else:
            md_f.write("No se encontraron vulnerabilidades de seguridad significativas durante el escaneo. Esto indica una buena postura de seguridad inicial, aunque se recomienda mantener un monitoreo continuo y realizar auditorías periódicas.\n\n")
        md_f.write("---\n\n")

        # --- Resumen de Hallazgos (Tabla y Gráfico ASCII) ---
        md_f.write("## Resumen de Hallazgos por Severidad\n\n")
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for finding in sorted_findings:
            sev = finding.get('info', {}).get('severity', 'unknown')
            severity_counts[sev] += 1
        
        md_f.write("| Severidad  | Cantidad | Visualización (Max 20) |\n")
        md_f.write("|:-----------|:---------|:-----------------------|\n")
        max_count = max(severity_counts.values()) if severity_counts else 1
        for sev_key in ["critical", "high", "medium", "low", "info", "unknown"]:
            count = severity_counts[sev_key]
            bar_length = int((count / max_count) * 20) if max_count > 0 else 0
            bar = "█" * bar_length
            md_f.write(f"| {sev_key.capitalize()} | {count:<8} | {bar:<20} |\n")
        md_f.write("\n---\n\n")

        # --- Detalles de los Hallazgos y Recomendaciones ---
        md_f.write("## Detalles de los Hallazgos\n\n")
        processed_recommendations = set() # Para no repetir recomendaciones

        for finding in sorted_findings:
            info = finding.get('info', {})
            name = info.get('name', 'N/A')
            severity = info.get('severity', 'info').upper()
            description = info.get('description', 'No description provided.')
            matched_at = finding.get('matched-at', 'N/A')
            curl_command = finding.get('curl-command', 'N/A')
            
            md_f.write(f"### **[{severity}]** - {name}\n\n")
            md_f.write(f"- **URL Afectada:** `{matched_at}`\n")
            md_f.write(f"- **Descripción:** {description}\n")
            if 'remediation' in info:
                md_f.write(f"- **Remediación Específica:** {info['remediation']}\n")
            md_f.write(f"- **Comando para Reproducir (cURL):**\n```bash\n{curl_command}\n```\n")

            # Añadir recomendación general basada en tags
            finding_tags = info.get('tags', [])
            added_recommendation = False
            for tag in finding_tags:
                if tag in RECOMMENDATION_MAP and tag not in processed_recommendations:
                    md_f.write(f"\n#### Recomendación General ({tag.capitalize()})\n")
                    md_f.write(f"{RECOMMENDATION_MAP[tag]}\n\n")
                    processed_recommendations.add(tag)
                    added_recommendation = True
                    break # Solo añadir una recomendación general por hallazgo para evitar redundancia
            
            if not added_recommendation and "default" not in processed_recommendations:
                md_f.write(f"\n#### Recomendación General\n")
                md_f.write(f"{RECOMMENDATION_MAP["default"]}\n\n")
                processed_recommendations.add("default")

            md_f.write("\n---\n\n")

            # Escribir al archivo raw
            raw_f.write(json.dumps(finding, indent=2) + "\n\n")

    print(f"[+] Reporte Markdown generado en: {report_md_path}")
    print(f"[+] Salida Raw completa generada en: {report_raw_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generador de Informes para AGHA.")
    parser.add_argument("workspace", help="La ruta al directorio del workspace que contiene los resultados JSONL.")
    args = parser.parse_args()

    if not os.path.isdir(args.workspace):
        print(f"[-] Error: El directorio del workspace no existe: {args.workspace}")
    else:
        generate_report(args.workspace)
