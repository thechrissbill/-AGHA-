import os
import json
import subprocess
import datetime
import argparse
import shutil
from queue import Queue
from multiprocessing import Pool, cpu_count
import ctypes

# --- CONFIGURACIÓN ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GRAYHUNTER_NUCLEI_PATH = os.path.join(SCRIPT_DIR, "scripts", "grayhunter-nuclei")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
TARGETS_FILE = os.path.join(SCRIPT_DIR, "targets.txt")
CPP_LIB_PATH = os.path.join(SCRIPT_DIR, "cpp_core", "libhighperf.so")

# Cargar la biblioteca C++
try:
    cpp_lib = ctypes.CDLL(CPP_LIB_PATH)
    # Definir la interfaz de las funciones C
    cpp_lib.create_high_performance_system.restype = ctypes.c_void_p
    cpp_lib.process_scan_result.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    cpp_lib.print_system_status.argtypes = [ctypes.c_void_p]
    cpp_lib.destroy_high_performance_system.argtypes = [ctypes.c_void_p]
    print(f"[*] Biblioteca C++ cargada exitosamente desde: {CPP_LIB_PATH}")
except OSError as e:
    print(f"[-] Error al cargar la biblioteca C++: {e}. Asegúrate de que {CPP_LIB_PATH} existe y es accesible.")
    cpp_lib = None # Marcar como no disponible

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

    # print(f"    [*] Ejecutando GrayHunter Nuclei para {target}: {' '.join(command)}") # Descomentar para depuración
    try:
        # Capturamos la salida para ver el progreso, pero grayhunter-nuclei ya escribe a archivos.
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        # print(f"    [+] GrayHunter Nuclei completado para {target}.") # Descomentar para depuración
        # print(process.stdout) # Descomentar para ver la salida completa de grayhunter-nuclei
        # print(process.stderr) # Descomentar para ver errores de grayhunter-nuclei
        return True
    except subprocess.CalledProcessError as e:
        print(f"    [-] Error al ejecutar GrayHunter Nuclei para {target}: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"[-] Error Fatal: El ejecutable 'grayhunter-nuclei' no se encontró en la ruta: {GRAYHUNTER_NUCLEI_PATH}")
        return False

def parse_results_for_triggers(json_file_path, cpp_system_ptr):
    """Parsea un archivo de resultados JSON y devuelve un set de tags encontrados.
       También envía cada hallazgo al sistema C++ para procesamiento optimizado."""
    detected_tags = set()
    if not os.path.exists(json_file_path):
        return detected_tags

    with open(json_file_path, 'r') as f:
        for line_num, line in enumerate(f):
            try:
                result = json.loads(line)
                tags = result.get('info', {}).get('tags', [])
                for tag in tags:
                    detected_tags.add(tag)
                
                # Enviar el hallazgo al sistema C++
                if cpp_lib and cpp_system_ptr:
                    request_id = f"{result.get('template-id', 'unknown')}_{result.get('matched-at', '')}_{line_num}"
                    cpp_lib.process_scan_result(
                        cpp_system_ptr,
                        request_id.encode('utf-8'),
                        line.encode('utf-8') # Enviar la línea JSON completa
                    )

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

    # Crear instancia del sistema C++ para este proceso (si la lib está disponible)
    cpp_system_instance = None
    if cpp_lib:
        cpp_system_instance = cpp_lib.create_high_performance_system()
        print(f"[*] Instancia del sistema C++ creada para {target}.")

    # Fase 1: Pipeline Base
    print("\n--- [FASE 1: EJECUTANDO PIPELINE BASE] ---")
    for step in BASE_PIPELINE:
        # Ejecutamos grayhunter-nuclei. Él se encarga de crear su directorio de sesión
        # y poner los resultados allí.
        if run_grayhunter_nuclei_command(target, step['args'], session_base_dir):
            # Necesitamos encontrar el directorio de sesión real que grayhunter-nuclei creó.
            # Buscamos el directorio más reciente dentro de session_base_dir que empiece con sanitized_target
            
            # Primero, asegurarnos de que el directorio base exista
            if not os.path.exists(session_base_dir):
                print(f"[-] Error: El directorio base de sesión {session_base_dir} no fue creado por GrayHunter Nuclei.")
                continue

            # Encontrar el directorio de sesión real creado por grayhunter-nuclei
            found_session_dir = None
            # Listar directorios y ordenar por fecha de modificación para encontrar el más reciente
            subdirs = [os.path.join(session_base_dir, d) for d in os.listdir(session_base_dir) if os.path.isdir(os.path.join(session_base_dir, d)) and d.startswith(sanitized_target)]
            if subdirs:
                found_session_dir = max(subdirs, key=os.path.getmtime)
            
            if not found_session_dir:
                print(f"[-] Error: No se encontró el directorio de sesión de GrayHunter Nuclei dentro de {session_base_dir}.")
                continue

            actual_session_dirs.append(found_session_dir)
            json_output_path = os.path.join(found_session_dir, step['output_json'])

            # 3. Análisis y Reacción
            # Pasamos el puntero al sistema C++ a la función de parseo
            print(f"    [*] Analizando resultados de '{step['name']}' para triggers en {json_output_path}...")
            found_tags = parse_results_for_triggers(json_output_path, cpp_system_instance)
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
            
            if run_grayhunter_nuclei_command(target, action['args'], base_session_dir_for_reactive):
                # Necesitamos encontrar el directorio de sesión real creado por grayhunter-nuclei
                # para esta tarea reactiva.
                found_reactive_session_dir = None
                subdirs = [os.path.join(base_session_dir_for_reactive, d) for d in os.listdir(base_session_dir_for_reactive) if os.path.isdir(os.path.join(base_session_dir_for_reactive, d)) and d.startswith(sanitized_target)]
                if subdirs:
                    found_reactive_session_dir = max(subdirs, key=os.path.getmtime)

                if found_reactive_session_dir:
                    actual_session_dirs.append(found_reactive_session_dir)
                else:
                    print(f"[-] Advertencia: No se encontró el directorio de sesión para la tarea reactiva {action['name']}.")

    print("\n--- [PIPELINE COMPLETADO] ---")
    print(f"[*] Todas las fases han finalizado para el objetivo: {target}")
    print(f"[*] Los directorios de sesión generados por GrayHunter Nuclei son: {actual_session_dirs}")
    
    # Imprimir métricas del sistema C++
    if cpp_lib and cpp_system_instance:
        print(f"\n[*] Métricas de rendimiento del sistema C++ para {target}:")
        cpp_lib.print_system_status(cpp_system_instance)
        cpp_lib.destroy_high_performance_system(cpp_system_instance)
        print(f"[*] Instancia del sistema C++ destruida para {target}.")

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