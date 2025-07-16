import os
import json
import subprocess
import datetime
import argparse
import shutil
from queue import Queue
from multiprocessing import Pool, cpu_count

# --- CONFIGURACIÓN ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NUCLEI_PATH = shutil.which("nuclei")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
TARGETS_FILE = os.path.join(SCRIPT_DIR, "targets.txt")

# ... (El resto de las definiciones de BASE_PIPELINE y VULN_REACTIVE_ACTIONS permanecen igual)
BASE_PIPELINE = [
    {"name": "1_Tech_Detection", "args": ["-t", "technologies/", "-tags", "tech"], "output": "1_tech_detection.json"},
    {"name": "2_Exposed_Panels", "args": ["-t", "http/exposed-panels/"], "output": "2_exposed_panels.json"},
    {"name": "3_Critical_CVEs", "args": ["-t", "cves/", "-s", "critical,high"], "output": "3_critical_cves.json"},
    {"name": "4_Common_Vulns", "args": ["-t", "http/vulnerabilities/", "-s", "medium", "-tags", "sqli,xss,rce"], "output": "4_common_vulns.json"},
    {"name": "5_Misconfigurations", "args": ["-t", "http/misconfiguration/"], "output": "5_misconfigurations.json"},
    {"name": "6_Subdomain_Takeovers", "args": ["-t", "http/takeovers/"], "output": "6_takeovers.json"},
    {"name": "7_Exposed_Secrets", "args": ["-t", "http/exposures/tokens/"], "output": "7_exposed_secrets.json"},
    {"name": "8_Headless_Scans", "args": ["-t", "headless/", "-headless"], "output": "8_headless_scans.json"},
]

VULN_REACTIVE_ACTIONS = {
    "cve": {"name": "CVE_Deep_Dive", "args": ["-t", "cves/", "-s", "critical,high,medium"], "output_suffix": "_cve_deep_dive.json"},
    "xss": {"name": "XSS_Deep_Dive", "args": ["-t", "http/xss/"], "output_suffix": "_xss_deep_dive.json"},
    "sqli": {"name": "SQLi_Deep_Dive", "args": ["-t", "http/sqli/"], "output_suffix": "_sqli_deep_dive.json"},
    "rce": {"name": "RCE_Deep_Dive", "args": ["-t", "http/technologies/"], "output_suffix": "_rce_deep_dive.json"},
    "panel": {"name": "Default_Logins", "args": ["-t", "http/default-logins/"], "output_suffix": "_default_logins.json"},
    "apache": {"name": "Apache_Specific_Vulns", "args": ["-t", "http/vulnerabilities/apache/"], "output_suffix": "_apache_vulns.json"},
    "nginx": {"name": "Nginx_Specific_Vulns", "args": ["-t", "http/vulnerabilities/nginx/"], "output_suffix": "_nginx_vulns.json"},
    "wordpress": {"name": "WordPress_Deep_Dive", "args": ["-t", "http/technologies/wordpress/"], "output_suffix": "_wordpress_deep_dive.json"},
    "CVE-2021-44228": {"name": "Log4Shell_Exploit_Attempt", "args": ["-t", "http/cves/2021/CVE-2021-44228.yaml"], "output_suffix": "_log4shell_exploit.json"},
    "info-disclosure": {"name": "Info_Disclosure_Deep_Dive", "args": ["-t", "http/miscellaneous/info-disclosure/"], "output_suffix": "_info_disclosure_deep_dive.json"},
    "lfi": {"name": "LFI_Deep_Dive", "args": ["-t", "http/file/lfi/"], "output_suffix": "_lfi_deep_dive.json"},
    "ssrf": {"name": "SSRF_Deep_Dive", "args": ["-t", "http/ssrf/"], "output_suffix": "_ssrf_deep_dive.json"},
    "open-redirect": {"name": "Open_Redirect_Deep_Dive", "args": ["-t", "http/miscellaneous/open-redirect.yaml"], "output_suffix": "_open_redirect_deep_dive.json"},
}

# --- FUNCIONES DE AYUDA (sin cambios) ---
def run_nuclei_command(target, command_args, output_path):
    """Ejecuta un comando de Nuclei y guarda la salida en formato JSONL."""
    if not NUCLEI_PATH:
        print(f"[-] Error Fatal para {target}: El ejecutable 'nuclei' no se encontró.")
        return False

    command = [
        NUCLEI_PATH, "-u", target, "-jsonl", "-o", output_path,
        "-silent", "-no-color", "-rate-limit", "150", "-c", "50", "-timeout", "10"
    ]
    command.extend(command_args)

    # print(f"    [*] Ejecutando para {target}: {' '.join(command)}") # Descomentar para depuración
    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        # print(f"    [-] Error al ejecutar Nuclei para {target}: {e}") # Descomentar para depuración
        return False

def parse_results_for_triggers(jsonl_file_path):
    detected_tags = set()
    if not os.path.exists(jsonl_file_path):
        return detected_tags
    with open(jsonl_file_path, 'r') as f:
        for line in f:
            try:
                result = json.loads(line)
                tags = result.get('info', {}).get('tags', [])
                for tag in tags:
                    detected_tags.add(tag)
            except json.JSONDecodeError:
                continue
    return detected_tags

# --- LÓGICA DEL PIPELINE POR OBJETIVO ---

def run_pipeline_for_target(target):
    """Ejecuta el pipeline completo para un único objetivo."""
    sanitized_target = target.replace('://', '_').replace('/', '_')
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    workspace_path = os.path.join(RESULTS_DIR, f"{sanitized_target}_{timestamp}")
    os.makedirs(workspace_path, exist_ok=True)
    
    print(f"[*] Pipeline Iniciado para: {target} | Workspace: {workspace_path}")

    reactive_queue = Queue()
    processed_reactive_actions = set()

    # Fase 1: Pipeline Base
    for step in BASE_PIPELINE:
        output_path = os.path.join(workspace_path, step['output'])
        if run_nuclei_command(target, step['args'], output_path):
            found_tags = parse_results_for_triggers(output_path)
            for tag in found_tags:
                if tag in VULN_REACTIVE_ACTIONS and tag not in processed_reactive_actions:
                    action = VULN_REACTIVE_ACTIONS[tag]
                    reactive_queue.put(action)
                    processed_reactive_actions.add(tag)

    # Fase 2: Tareas Reactivas
    if not reactive_queue.empty():
        print(f"[*] Procesando {reactive_queue.qsize()} tareas reactivas para {target}...")
        while not reactive_queue.empty():
            action = reactive_queue.get()
            output_filename = f"{sanitized_target}{action['output_suffix']}"
            output_path = os.path.join(workspace_path, output_filename)
            run_nuclei_command(target, action['args'], output_path)

    print(f"[+] Pipeline Completado para: {target}")
    return workspace_path

# --- PUNTO DE ENTRADA PRINCIPAL ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AGHA - Pipeline de Escaneo Reactivo con Nuclei para Múltiples Objetivos.")
    parser.add_argument("-c", "--concurrency", type=int, default=cpu_count(), help=f"Número de objetivos a escanear en paralelo. Por defecto: número de CPUs ({cpu_count()}).")
    args = parser.parse_args()

    # Leer objetivos desde el archivo
    if not os.path.exists(TARGETS_FILE):
        print(f"[-] Error: El archivo de objetivos '{TARGETS_FILE}' no se encontró.")
        exit(1)

    with open(TARGETS_FILE, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    if not targets:
        print("[-] Error: El archivo de objetivos está vacío.")
        exit(1)

    print(f"[*] AGHA Iniciado. {len(targets)} objetivos cargados. Concurrencia: {args.concurrency}.")
    start_time = datetime.datetime.now()

    # Crear y ejecutar el pool de procesos
    with Pool(processes=args.concurrency) as pool:
        workspaces = pool.map(run_pipeline_for_target, targets)

    end_time = datetime.datetime.now()
    print(f"\n--- [TODOS LOS ESCANEOS COMPLETADOS] ---")
    print(f"Duración total: {end_time - start_time}")
    print("Workspaces generados:")
    for ws in workspaces:
        print(f"  - {ws}")
    print("\n[*] Para generar un informe consolidado para un workspace, ejecuta:")
    print(f"[*] python3 report_generator.py <ruta_al_workspace>")