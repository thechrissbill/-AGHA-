# GEMINI.md - Guía para el Agente Gemini (AGHA Project)

Este documento proporciona una guía para el Agente Gemini sobre la estructura, propósito y operación del proyecto **AGHA (Autonomous Grayhat Agent)**.

## 1. Visión General del Proyecto

**Nombre:** AGHA - Autonomous Grayhat Agent
**Propósito:** AGHA es un pipeline de escaneo de vulnerabilidades inteligente y reactivo diseñado para automatizar y profundizar en las evaluaciones de seguridad utilizando la herramienta Nuclei. Su objetivo es simular el flujo de trabajo de un analista de seguridad humano, reaccionando a los hallazgos iniciales para realizar investigaciones más específicas y generar informes profesionales.

## 2. Estructura del Proyecto y Archivos Clave

El proyecto AGHA reside en el directorio `/home/bill/AGHA/` y consta de los siguientes archivos y directorios principales:

-   `agha_pipeline.py`: **El orquestador principal.** Este script gestiona todo el proceso de escaneo.
    -   Lee objetivos de `targets.txt`.
    -   Ejecuta un pipeline base de escaneos de Nuclei.
    -   Analiza los resultados de cada paso para identificar "triggers" (vulnerabilidades o tecnologías detectadas).
    -   Añade tareas de profundización (escaneos reactivos) a una cola.
    -   Ejecuta las tareas reactivas una vez que el pipeline base ha finalizado.
    -   Utiliza `multiprocessing` para escanear múltiples objetivos en paralelo.
-   `report_generator.py`: **El generador de informes.** Este script se encarga de consolidar todos los resultados de los escaneos (tanto del pipeline base como de los reactivos) en un informe Markdown profesional y un archivo JSON en bruto.
-   `targets.txt`: **Archivo de configuración de objetivos.** Contiene una lista de URLs o dominios, uno por línea, que AGHA escaneará.
-   `results/`: **Directorio de salida.** Aquí se crean subdirectorios para cada escaneo de objetivo (ej. `results/http_ejemplo.com_YYYYMMDD_HHMMSS/`). Cada subdirectorio contiene los archivos JSONL de los escaneos base y reactivos, así como el informe final en Markdown y el archivo raw.

## 3. Requisitos y Dependencias

-   **Python 3:** El entorno de ejecución para los scripts de AGHA.
-   **Nuclei:** La herramienta de escaneo de vulnerabilidades. Debe estar instalada y accesible en el `PATH` del sistema. AGHA utiliza `shutil.which("nuclei")` para localizarlo.
-   **Plantillas de Nuclei:** Las plantillas de Nuclei deben estar actualizadas (`nuclei -update-templates`). AGHA asume que las plantillas están en la ubicación por defecto de Nuclei o que Nuclei puede encontrarlas.

## 4. Flujo de Operación (Cómo usar AGHA)

1.  **Configurar Objetivos:** Edita el archivo `targets.txt` y añade las URLs o dominios que deseas escanear, uno por línea.
2.  **Ejecutar el Pipeline de Escaneo:**
    ```bash
    python3 agha_pipeline.py [-c <concurrency>]
    ```
    -   `<concurrency>` (opcional): Número de objetivos a escanear en paralelo. Por defecto, usa el número de CPUs.
    -   El script creará un directorio de resultados para cada objetivo en `results/`.
3.  **Generar Informes:** Una vez que `agha_pipeline.py` haya terminado, te proporcionará la ruta a los directorios de resultados de cada objetivo. Para generar un informe profesional para un objetivo específico:
    ```bash
    python3 report_generator.py <ruta_al_workspace_del_objetivo>
    ```
    -   Ejemplo: `python3 report_generator.py results/http_ejemplo.com_20250715_123456`
    -   Esto creará `_Hunter_Report.md` y `_Full_Raw_Output.txt` dentro del directorio del workspace.

## 5. Lógica de Inteligencia (Para el Agente)

-   **`BASE_PIPELINE` (en `agha_pipeline.py`):** Define la secuencia de escaneos iniciales. Si se requiere añadir nuevos pasos de reconocimiento general, se deben añadir aquí.
-   **`VULN_REACTIVE_ACTIONS` (en `agha_pipeline.py`):** Este diccionario es el corazón de la inteligencia reactiva. Mapea los `tags` de vulnerabilidad o tecnología detectados por Nuclei a comandos de Nuclei adicionales para una profundización específica.
    -   **Para expandir la inteligencia:** Añadir nuevas entradas a este diccionario, asociando un `tag` (que Nuclei podría emitir) con una lista de argumentos de Nuclei para un escaneo más dirigido.
    -   Asegurarse de que los `tags` utilizados en `VULN_REACTIVE_ACTIONS` coincidan con los `tags` que las plantillas de Nuclei emiten.
-   **`RECOMMENDATION_MAP` (en `report_generator.py`):** Contiene recomendaciones genéricas para diferentes tipos de vulnerabilidades.
    -   **Para mejorar las recomendaciones:** Añadir o refinar entradas en este mapa, asociando un `tag` de vulnerabilidad con un texto de recomendación detallado.

## 6. Consideraciones para el Agente

-   **Rutas Absolutas:** Siempre construye rutas absolutas utilizando `os.path.join(SCRIPT_DIR, ...)` para asegurar la portabilidad.
-   **Manejo de Errores:** Los scripts ya incluyen manejo básico de errores. Si se encuentran problemas con la ejecución de Nuclei o el parseo de JSON, se deben reportar al usuario.
-   **Depuración:** Para depurar la ejecución de comandos de Nuclei, puedes descomentar las líneas `print` dentro de `run_nuclei_command` en `agha_pipeline.py`.
-   **Actualizaciones:** Si se solicita actualizar Nuclei o sus plantillas, se debe usar `nuclei -update` o `nuclei -update-templates` respectivamente.
