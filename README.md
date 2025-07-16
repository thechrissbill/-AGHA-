# AGHA: Autonomous Grayhat Agent

AGHA (Autonomous Grayhat Agent) es un sistema avanzado de escaneo de vulnerabilidades diseñado para automatizar y optimizar el proceso de evaluación de seguridad. Utilizando la potente herramienta Nuclei, AGHA implementa un pipeline reactivo que simula el flujo de trabajo de un analista de seguridad experimentado, profundizando en los hallazgos iniciales para generar informes de auditoría detallados y accionables.

## Características Principales

-   **Escaneo Reactivo Inteligente:** AGHA no solo ejecuta escaneos predefinidos, sino que también analiza los resultados en tiempo real. Las vulnerabilidades o tecnologías detectadas actúan como "triggers" que desencadenan automáticamente escaneos de profundización específicos, asegurando una cobertura exhaustiva y contextual.
-   **Paralelismo de Alto Rendimiento:** Capaz de escanear múltiples objetivos simultáneamente, aprovechando al máximo los recursos del sistema para reducir drásticamente el tiempo total de evaluación.
-   **Informes de Auditoría Profesionales:** Genera informes en formato Markdown que incluyen:
    -   Un resumen ejecutivo claro y conciso.
    -   Un gráfico visual de la distribución de severidades de los hallazgos.
    -   Detalles técnicos de cada vulnerabilidad, incluyendo comandos para su reproducción.
    -   Recomendaciones de remediación generales y específicas, basadas en las mejores prácticas de seguridad.
-   **Modular y Extensible:** Diseñado con una arquitectura modular que facilita la adición de nuevos pasos de escaneo, la expansión de la lógica reactiva y la integración de futuras herramientas de seguridad.

## Cómo Funciona

AGHA opera a través de un pipeline de tres fases:

1.  **Pipeline Base:** Ejecuta una serie de escaneos generales de Nuclei (detección de tecnología, paneles expuestos, CVEs críticos, etc.).
2.  **Motor Reactivo:** Analiza la salida de cada paso del pipeline base. Si se detectan "triggers" (ej. una tecnología específica o una vulnerabilidad de alto impacto), se añaden tareas de profundización a una cola.
3.  **Ejecución Reactiva:** Una vez completado el pipeline base, AGHA procesa la cola de tareas reactivas, ejecutando escaneos de Nuclei altamente dirigidos para validar y obtener más detalles sobre los hallazgos iniciales.
4.  **Generación de Informes:** Finalmente, todos los resultados se consolidan en un informe Markdown estructurado y un archivo JSON en bruto, listos para su revisión y acción.

## Requisitos

-   Python 3
-   Nuclei (instalado y en el PATH del sistema)
-   Plantillas de Nuclei actualizadas

## Uso

1.  **Configurar Objetivos:** Edite `targets.txt` con las URLs o dominios a escanear (uno por línea).
2.  **Ejecutar AGHA:**
    ```bash
    python3 agha_pipeline.py [-c <concurrency>]
    ```
    (Donde `<concurrency>` es el número de procesos paralelos, por defecto el número de CPUs).
3.  **Generar Informe:** Una vez que `agha_pipeline.py` finalice, use la ruta del workspace proporcionada para generar el informe:
    ```bash
    python3 report_generator.py <ruta_al_workspace>
    ```

AGHA transforma el escaneo de vulnerabilidades en un proceso más eficiente, inteligente y con resultados de alta calidad, permitiendo a los equipos de seguridad enfocarse en la remediación y la estrategia.
# -AGHA-
