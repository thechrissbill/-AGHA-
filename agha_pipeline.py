

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
GRAYHUNTER_NUCLEI_PATH = os.path.join(SCRIPT_DIR, "scripts", "grayhunter-nuclei")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
TARGETS_FILE = os.path.join(SCRIPT_DIR, "targets.txt")

# 1. DEFINICIÓN DEL PIPELINE BASE
# Una secuencia de escaneos que se ejecutan en orden.
# Los 'args' ahora son para grayhunter-nuclei, no para nuclei directamente.
BASE_PIPELINE = [
    {"name": "1_Tech_Detection", "args": ["-templates", "technologies/", "-tags", "tech"], "output_json": "nuclei_results.json"},
    {"name": "2_Exposed_Panels", "args": ["-templates", "http/exposed-panels/"], "output_json": "nuclei_results.json"},
    {"name": "3_Critical_CVEs", "args": ["-templates", "cves/", "-severity", "critical,high"], "output_json": "nuclei_results.json"},
    {"name": "4_Common_Vulns", "args": ["-templates", "http/vulnerabilities/", "-severity", "medium", "-tags", "sqli,xss,rce"], "output_json": "nuclei_results.json"},
    {"name": "5_Misconfigurations", "args": ["-templates", "http/misconfiguration/"], "output_json": "nuclei_results.json"},
    {"name": "6_Subdomain_Takeovers", "args": ["-templates", "http/takeovers/"], "output_json": "nuclei_results.json"},
    {"name": "7_Exposed_Secrets", "args": ["-templates", "http/exposures/tokens/"], "output_json": "nuclei_results.json"},
    {"name": "8_Headless_Scans", "args": ["-templates", "headless/", "-headless"], "output_json": "nuclei_results.json"},
]

# 2. DEFINICIÓN DE TRIGGERS Y ACCIONES REACTIVAS
# Mapea un 'tag' de Nuclei a un escaneo de profundización.
# Los 'args' ahora son para grayhunter-nuclei.
VULN_REACTIVE_ACTIONS = {
    "cve": {"name": "CVE_Deep_Dive", "args": ["-templates", "cves/", "-severity", "critical,high,medium"], "output_json": "nuclei_results.json"},
    "xss": {"name": "XSS_Deep_Dive", "args": ["-templates", "http/xss/"], "output_json": "nuclei_results.json"},
    "sqli": {"name": "SQLi_Deep_Dive", "args": ["-templates", "http/sqli/"], "output_json": "nuclei_results.json"},
    "rce": {"name": "RCE_Deep_Dive", "args": ["-templates", "http/technologies/"], "output_json": "nuclei_results.json"},
    "panel": {"name": "Default_Logins", "args": ["-templates", "http/default-logins/"], "output_json": "nuclei_results.json"},
    "apache": {"name": "Apache_Specific_Vulns", "args": ["-templates", "http/vulnerabilities/apache/"], "output_json": "nuclei_results.json"},
    "nginx": {"name": "Nginx_Specific_Vulns", "args": ["-templates", "http/vulnerabilities/nginx/"], "output_json": "nuclei_results.json"},
    "wordpress": {"name": "WordPress_Deep_Dive", "args": ["-templates", "http/technologies/wordpress/"], "output_json": "nuclei_results.json"},
    "CVE-2021-44228": {"name": "Log4Shell_Exploit_Attempt", "args": ["-templates", "http/cves/2021/CVE-2021-44228.yaml"], "output_json": "nuclei_results.json"},
    "info-disclosure": {"name": "Info_Disclosure_Deep_Dive", "args": ["-templates", "http/miscellaneous/info-disclosure/"], "output_json": "nuclei_results.json"},
    "lfi": {"name": "LFI_Deep_Dive", "args": ["-templates", "http/file/lfi/"], "output_json": "nuclei_results.json"},
    "ssrf": {"name": "SSRF_Deep_Dive", "args": ["-templates", "http/ssrf/"], "output_json": "nuclei_results.json"},
    "open-redirect": {"name": "Open_Redirect_Deep_Dive", "args": ["-templates", "http/miscellaneous/open-redirect.yaml"], "output_json": "nuclei_results.json"},
}

# --- FUNCIONES DE AYUDA ---

def run_grayhunter_nuclei_command(target, command_args, session_output_dir):
    """Ejecuta grayhunter-nuclei y espera a que termine."""
    if not os.path.exists(GRAYHUNTER_NUCLEI_PATH):
        print(f"[-] Error Fatal para {target}: El ejecutable 'grayhunter-nuclei' no se encontró en {GRAYHUNTER_NUCLEI_PATH}.")
        return False

    # grayhunter-nuclei ya maneja la creación de su propio directorio de sesión
    # y la salida JSON dentro de él. Solo necesitamos pasarle el target y los args.
    command = [
        GRAYHUNTER_NUCLEI_PATH,
        "-target", target, # grayhunter-nuclei espera -target para un solo objetivo
        "-output-dir", session_output_dir, # Le decimos dónde crear su directorio de sesión
    ]
    command.extend(command_args)

    print(f"    [*] Ejecutando GrayHunter Nuclei para {target}: {' '.join(command)}")
    try:
        # Capturamos la salida para ver el progreso, pero grayhunter-nuclei ya escribe a archivos.
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"    [+] GrayHunter Nuclei completado para {target}.")
        # print(process.stdout) # Descomentar para ver la salida completa de grayhunter-nuclei
        # print(process.stderr) # Descomentar para ver errores de grayhunter-nuclei
        return True
    except subprocess.CalledProcessError as e:
        print(f"    [-] Error al ejecutar GrayHunter Nuclei para {target}: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"[-] Error Fatal: El ejecutable 'grayhunter-nuclei' no se encontró en la ruta: {GRAYHUNTER_NUCLEI_PATH}")
        return False

def parse_results_for_triggers(jsonl_file_path):
    """Parsea un archivo de resultados JSONL y devuelve un set de tags encontrados."""
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
    # grayhunter-nuclei creará su propio directorio de sesión.
    # Necesitamos un nombre base para ese directorio.
    sanitized_target = target.replace('://', '_').replace('/', '_')
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # El output_dir de grayhunter-nuclei será dentro de nuestro RESULTS_DIR
    session_base_dir = os.path.join(RESULTS_DIR, f"{sanitized_target}_{timestamp}")
    
    print(f"[*] Pipeline Iniciado para: {target} | Sesión base en: {session_base_dir}")

    reactive_queue = Queue()
    processed_reactive_actions = set()
    
    # Almacenaremos las rutas reales de los directorios de sesión creados por grayhunter-nuclei
    # para poder pasarlas al report_generator.
    actual_session_dirs = []

    # Fase 1: Pipeline Base
    print("\n--- [FASE 1: EJECUTANDO PIPELINE BASE] ---")
    for step in BASE_PIPELINE:
        # grayhunter-nuclei creará un subdirectorio dentro de session_base_dir
        # con un timestamp. Necesitamos capturar ese nombre.
        # Por simplicidad, le pasaremos el session_base_dir y esperaremos que
        # grayhunter-nuclei cree su directorio de sesión dentro.
        
        # Ejecutamos grayhunter-nuclei. Él se encarga de crear su directorio de sesión
        # y poner los resultados allí.
        if run_grayhunter_nuclei_command(target, step['args'], session_base_dir):
            # Necesitamos encontrar el directorio de sesión real que grayhunter-nuclei creó.
            # Esto es un poco hacky, pero grayhunter-nuclei usa el formato <sanitized_target>_<timestamp>
            # dentro del output_dir que le pasamos.
            # Buscamos el directorio más reciente dentro de session_base_dir que empiece con sanitized_target
            
            # Primero, asegurarnos de que el directorio base exista
            if not os.path.exists(session_base_dir):
                print(f"[-] Error: El directorio base de sesión {session_base_dir} no fue creado por GrayHunter Nuclei.")
                continue

            # Encontrar el directorio de sesión real creado por grayhunter-nuclei
            # Listamos los contenidos y buscamos el que coincida con el patrón de nombre
            found_session_dir = None
            for d_name in os.listdir(session_base_dir):
                if d_name.startswith(sanitized_target):
                    full_path = os.path.join(session_base_dir, d_name)
                    if os.path.isdir(full_path):
                        # Asumimos que el más reciente es el que acabamos de crear
                        # Esto podría ser problemático si se ejecutan múltiples escaneos muy rápido
                        # Una solución más robusta sería que grayhunter-nuclei devolviera la ruta
                        # de su directorio de sesión en stdout/stderr.
                        found_session_dir = full_path
                        break # Asumimos que el primero que encontramos es el correcto
            
            if not found_session_dir:
                print(f"[-] Error: No se encontró el directorio de sesión de GrayHunter Nuclei dentro de {session_base_dir}.")
                continue

            actual_session_dirs.append(found_session_dir)
            json_output_path = os.path.join(found_session_dir, step['output_json'])

            # 3. Análisis y Reacción
            print(f"    [*] Analizando resultados de '{step['name']}' para triggers en {json_output_path}...")
            found_tags = parse_results_for_triggers(json_output_path)
            for tag in found_tags:
                if tag in VULN_REACTIVE_ACTIONS and tag not in processed_reactive_actions:
                    action = VULN_REACTIVE_ACTIONS[tag]
                    print(f"    [!] Trigger detectado: '{tag}'. Añadiendo acción reactiva '{action['name']}' a la cola.")
                    reactive_queue.put((action, found_session_dir)) # Guardamos la acción y el directorio de sesión base
                    processed_reactive_actions.add(tag) # Evita añadir la misma acción múltiples veces

    # Fase 2: Ejecución de Tareas Reactivas
    print("\n--- [FASE 2: PROCESANDO TAREAS REACTIVAS] ---")
    if reactive_queue.empty():
        print("  -> No se generaron tareas reactivas.")
    else:
        while not reactive_queue.empty():
            action, base_session_dir_for_reactive = reactive_queue.get()
            print(f"\n  -> Ejecutando acción reactiva: {action['name']}")
            # Para las tareas reactivas, grayhunter-nuclei creará un nuevo subdirectorio
            # dentro del directorio de sesión base del paso que disparó el trigger.
            # Le pasamos el directorio base de la sesión original.
            if run_grayhunter_nuclei_command(target, action['args'], base_session_dir_for_reactive):
                # Necesitamos encontrar el directorio de sesión real creado por grayhunter-nuclei
                # para esta tarea reactiva.
                found_reactive_session_dir = None
                for d_name in os.listdir(base_session_dir_for_reactive):
                    if d_name.startswith(sanitized_target) and d_name != os.path.basename(base_session_dir_for_reactive):
                        full_path = os.path.join(base_session_dir_for_reactive, d_name)
                        if os.path.isdir(full_path):
                            found_reactive_session_dir = full_path
                            break
                if found_reactive_session_dir:
                    actual_session_dirs.append(found_reactive_session_dir)
                else:
                    print(f"[-] Advertencia: No se encontró el directorio de sesión para la tarea reactiva {action['name']}.")

    print("\n--- [PIPELINE COMPLETADO] ---")
    print(f"[*] Todas las fases han finalizado para el objetivo: {target}")
    print(f"[*] Los directorios de sesión generados por GrayHunter Nuclei son: {actual_session_dirs}")
    print(f"[*] Para generar un informe consolidado, ejecuta: python3 report_generator.py <ruta_al_workspace_principal>")
    
    # Devolvemos el directorio base que contiene todos los subdirectorios de sesión
    return session_base_dir

# --- PUNTO DE ENTRADA PRINCIPAL ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AGHA - Pipeline de Escaneo Reactivo con GrayHunter Nuclei para Múltiples Objetivos.")
    parser.add_argument("-c", "--concurrency", type=int, default=cpu_count(), help=f"Número de objetivos a escanear en paralelo. Por defecto: número de CPUs ({cpu_count()}).")
    args = parser.parse_args()

    # Leer objetivos desde el archivo
    if not os.path.exists(TARGETS_FILE):
        print(f"[-] Error: El archivo de objetivos '{TARGETS_FILE}' no se encontró en {TARGETS_FILE}.")
        exit(1)

    with open(TARGETS_FILE, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    if not targets:
        print("[-] Error: El archivo de objetivos está vacío.")
        exit(1)

    print(f"[*] AGHA Iniciado. {len(targets)} objetivos cargados. Concurrencia: {args.concurrency}.")
    start_time = datetime.datetime.now()

    # Crear y ejecutar el pool de procesos
    # Pasamos el RESULTS_DIR a cada proceso para que grayhunter-nuclei sepa dónde crear sus directorios de sesión
    # y para que el report_generator pueda encontrarlos.
    
    # Modificamos run_pipeline_for_target para que devuelva el directorio base de la sesión
    # que contiene todos los subdirectorios de grayhunter-nuclei.
    with Pool(processes=args.concurrency) as pool:
        # pool.map devuelve una lista de los valores de retorno de run_pipeline_for_target
        base_workspaces = pool.map(run_pipeline_for_target, targets)

    end_time = datetime.datetime.now()
    print(f"\n--- [TODOS LOS ESCANEOS COMPLETADOS] ---")
    print(f"Duración total: {end_time - start_time}")
    print("Workspaces base generados:")
    for ws in base_workspaces:
        print(f"  - {ws}")
    print("\n[*] Para generar un informe consolidado para un workspace base, ejecuta:")
    print(f"[*] python3 report_generator.py <ruta_al_workspace_base>")
