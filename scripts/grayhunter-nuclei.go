// grayhunter-nuclei.go
// Escaneo con Nuclei mejorado - GrayHunter con logging detallado y manejo de errores
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Colores para output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// Configuración del scanner
type Config struct {
	TargetsFile     string
	Concurrency     int
	RateLimit       int
	Timeout         int
	Retries         int
	Severity        []string
	Tags            []string
	Templates       string
	UpdateTemplates bool
	Headless        bool
	NoInteractsh    bool
	StatsInterval   int
	UserAgent       string
	OutputDir       string
	ProjectName     string
}

// Estructura para estadísticas
type ScanStats struct {
	StartTime       time.Time
	EndTime         time.Time
	TotalTargets    int
	TargetsScanned  int
	VulnsFound      int
	HighVulns       int
	CriticalVulns   int
	TemplatesUsed   int
	Errors          int
	mu              sync.RWMutex
}

// Scanner principal
type NucleiScanner struct {
	config    *Config
	stats     *ScanStats
	sessionDir string
	ctx       context.Context
	cancel    context.CancelFunc
	logger    *log.Logger
}

func printColored(color, prefix, message string) {
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s %s]%s %s\n", color, timestamp, prefix, ColorReset, message)
}

func printSuccess(message string) {
	printColored(ColorGreen, "✓", message)
}

func printError(message string) {
	printColored(ColorRed, "✗", message)
}

func printInfo(message string) {
	printColored(ColorBlue, "i", message)
}

func printWarning(message string) {
	printColored(ColorYellow, "!", message)
}

func printBanner() {
	banner := `
%s╔═══════════════════════════════════════════════════════════════════════════════╗
║                           GrayHunter Nuclei Scanner                          ║
║                              Version 2.0 Enhanced                           ║
╚═══════════════════════════════════════════════════════════════════════════════╝%s
`
	fmt.Printf(banner, ColorPurple+ColorBold, ColorReset)
}

// Configuración por defecto
func defaultConfig() *Config {
	return &Config{
		TargetsFile:     "../targets.txt",
		Concurrency:     25,
		RateLimit:       100,
		Timeout:         15,
		Retries:         2,
		Severity:        []string{"info", "low", "medium", "high", "critical"},
		Tags:            []string{"cve", "xss", "sqli", "lfi", "rfi", "rce", "ssrf", "open-redirect", "token", "exposure", "takeover", "misconfig", "tech"},
		Templates:       "",
		UpdateTemplates: true,
		Headless:        true,
		NoInteractsh:    false,
		StatsInterval:   10,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		OutputDir:       "",
		ProjectName:     "",
	}
}

// Cargar configuración desde archivo JSON (opcional)
func loadConfig(configPath string) (*Config, error) {
	config := defaultConfig()
	
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			data, err := os.ReadFile(configPath)
			if err != nil {
				return nil, fmt.Errorf("error leyendo archivo de configuración: %v", err)
			}
			
			if err := json.Unmarshal(data, config); err != nil {
				return nil, fmt.Errorf("error parseando configuración JSON: %v", err)
			}
			
			printSuccess("Configuración cargada desde archivo")
		}
	}
	
	return config, nil
}

// Crear nuevo scanner
func NewNucleiScanner(config *Config) *NucleiScanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &NucleiScanner{
		config: config,
		stats: &ScanStats{
			StartTime: time.Now(),
		},
		ctx:    ctx,
		cancel: cancel,
		logger: log.New(os.Stdout, "[SCANNER] ", log.LstdFlags),
	}
}

func (ns *NucleiScanner) checkDependencies() error {
	printInfo("Verificando dependencias...")
	
	// Verificar si nuclei está instalado
	if _, err := exec.LookPath("nuclei"); err != nil {
		return fmt.Errorf("nuclei no está instalado o no está en PATH")
	}
	
	// Verificar version de nuclei
	cmd := exec.Command("nuclei", "-version")
	output, err := cmd.Output()
	if err != nil {
		printWarning("No se pudo verificar la versión de nuclei")
	} else {
		version := strings.TrimSpace(string(output))
		printInfo(fmt.Sprintf("Versión de nuclei: %s", version))
	}
	
	// Verificar templates de nuclei
	templatesPath := ns.config.Templates
	if templatesPath == "" {
		templatesPath = filepath.Join(os.Getenv("HOME"), "nuclei-templates")
	}
	
	if _, err := os.Stat(templatesPath); os.IsNotExist(err) {
		printWarning(fmt.Sprintf("Templates no encontrados en: %s", templatesPath))
		printInfo("Nuclei descargará templates automáticamente")
	} else {
		printSuccess("Templates encontrados")
	}
	
	printSuccess("Dependencias verificadas")
	return nil
}

func (ns *NucleiScanner) validateTargetsFile() ([]string, error) {
	printInfo(fmt.Sprintf("Validando archivo de objetivos: %s", ns.config.TargetsFile))
	
	if _, err := os.Stat(ns.config.TargetsFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("archivo de objetivos no encontrado: %s", ns.config.TargetsFile)
	}
	
	file, err := os.Open(ns.config.TargetsFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir el archivo: %v", err)
	}
	defer file.Close()
	
	var targets []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Ignorar líneas vacías y comentarios
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Validación básica de formato
		if !strings.Contains(line, ".") {
			printWarning(fmt.Sprintf("Línea %d: formato sospechoso: %s", lineNum, line))
		}
		
		targets = append(targets, line)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error leyendo archivo: %v", err)
	}
	
	if len(targets) == 0 {
		return nil, fmt.Errorf("no se encontraron objetivos válidos en el archivo")
	}
	
	ns.stats.TotalTargets = len(targets)
	printSuccess(fmt.Sprintf("Encontrados %d objetivos válidos", len(targets)))
	return targets, nil
}

func (ns *NucleiScanner) sanitizeFileName(name string) string {
	replacements := map[string]string{
		"http://":  "",
		"https://": "",
		":":        "_",
		"/":        "_",
		"\\":       "_",
		"?":        "_",
		"*":        "_",
		"<":        "_",
		">":        "_",
		"|":        "_",
		"\"":       "_",
		" ":        "_",
	}
	
	for old, new := range replacements {
		name = strings.ReplaceAll(name, old, new)
	}
	
	// Limitar longitud
	if len(name) > 50 {
		name = name[:50]
	}
	
	return name
}

func (ns *NucleiScanner) createSessionDirectory(firstTarget string) error {
	date := time.Now().Format("2006-01-02_15-04-05")
	sanitizedTarget := ns.sanitizeFileName(firstTarget)
	
	if ns.config.ProjectName != "" {
		sanitizedTarget = ns.config.ProjectName
	}
	
	baseDir := ns.config.OutputDir
	if baseDir == "" {
		baseDir = filepath.Join(os.Getenv("HOME"), "AGHA", "results")
	}
	
	ns.sessionDir = filepath.Join(baseDir, fmt.Sprintf("%s_%s", sanitizedTarget, date))
	
	if err := os.MkdirAll(ns.sessionDir, 0755); err != nil {
		return fmt.Errorf("no se pudo crear directorio de sesión: %v", err)
	}
	
	printSuccess(fmt.Sprintf("Directorio de sesión creado: %s", ns.sessionDir))
	return nil
}

func (ns *NucleiScanner) copyFile(src, dest string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	
	destinationFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destinationFile.Close()
	
	_, err = io.Copy(destinationFile, sourceFile)
	return err
}

func (ns *NucleiScanner) buildNucleiCommand() []string {
	// Archivos de salida
	rawOutput := filepath.Join(ns.sessionDir, "nuclei_raw_output.txt")
	jsonOutput := filepath.Join(ns.sessionDir, "nuclei_results.json")
	reportMarkdown := filepath.Join(ns.sessionDir, "nuclei_report.md")
	projectPath := filepath.Join(ns.sessionDir, "nuclei-project")
	
	args := []string{
		"-l", ns.config.TargetsFile,
		"-s", strings.Join(ns.config.Severity, ","),
		"-c", strconv.Itoa(ns.config.Concurrency),
		"-rate-limit", strconv.Itoa(ns.config.RateLimit),
		"-timeout", strconv.Itoa(ns.config.Timeout),
		"-retries", strconv.Itoa(ns.config.Retries),
		"-H", fmt.Sprintf("User-Agent: %s", ns.config.UserAgent),
		"-H", "X-Forwarded-For: 127.0.0.1",
		"-H", "Referer: https://www.google.com",
		"-project",
		"-project-path", projectPath,
		"-stats",
		"-stats-interval", strconv.Itoa(ns.config.StatsInterval),
		"-markdown-export", reportMarkdown,
		"-json-export", jsonOutput,
		"-o", rawOutput,
		"-v",
	}
	
	// Templates
	if ns.config.Templates != "" {
		args = append(args, "-t", ns.config.Templates)
	}
	
	// Tags
	if len(ns.config.Tags) > 0 {
		args = append(args, "-tags", strings.Join(ns.config.Tags, ","))
	}
	
	// Opciones adicionales
	if ns.config.Headless {
		args = append(args, "-headless")
	}
	
	if ns.config.NoInteractsh {
		args = append(args, "-no-interactsh")
	}
	
	if ns.config.UpdateTemplates {
		args = append(args, "-update-templates")
	}
	
	return args
}

func (ns *NucleiScanner) runScan() error {
	printInfo("Configurando escaneo Nuclei...")
	
	// Crear archivo de log detallado
	logFile, err := os.Create(filepath.Join(ns.sessionDir, "scan_log.txt"))
	if err != nil {
		return fmt.Errorf("no se pudo crear archivo de log: %v", err)
	}
	defer logFile.Close()
	
	// Construir comando
	nucleiArgs := ns.buildNucleiCommand()
	
	// Mostrar comando completo
	printInfo("Comando a ejecutar:")
	fmt.Printf("nuclei %s\n", strings.Join(nucleiArgs, " "))
	
	// Guardar comando en archivo
	cmdFile, _ := os.Create(filepath.Join(ns.sessionDir, "command.txt"))
	cmdFile.WriteString(fmt.Sprintf("nuclei %s\n", strings.Join(nucleiArgs, " ")))
	cmdFile.Close()
	
	// Ejecutar nuclei con context
	cmd := exec.CommandContext(ns.ctx, "nuclei", nucleiArgs...)
	
	// Capturar salidas
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creando pipe stdout: %v", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creando pipe stderr: %v", err)
	}
	
	// Iniciar comando
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error iniciando nuclei: %v", err)
	}
	
	// WaitGroup para manejar goroutines
	var wg sync.WaitGroup
	
	// Leer stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) != "" {
				fmt.Printf("[%sNUCLEI%s] %s\n", ColorCyan, ColorReset, line)
				logFile.WriteString(fmt.Sprintf("[STDOUT] %s\n", line))
				
				// Actualizar estadísticas basadas en salida
				ns.updateStatsFromOutput(line)
			}
		}
	}()
	
	// Leer stderr
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) != "" {
				fmt.Printf("[%sNUCLEI ERR%s] %s\n", ColorYellow, ColorReset, line)
				logFile.WriteString(fmt.Sprintf("[STDERR] %s\n", line))
				
				if strings.Contains(strings.ToLower(line), "error") {
					ns.stats.mu.Lock()
					ns.stats.Errors++
					ns.stats.mu.Unlock()
				}
			}
		}
	}()
	
	// Esperar a que termine el comando
	err = cmd.Wait()
	
	// Esperar a que terminen las goroutines
	wg.Wait()
	
	ns.stats.EndTime = time.Now()
	
	if err != nil {
		if ns.ctx.Err() == context.Canceled {
			printWarning("Escaneo cancelado por el usuario")
		} else {
			printWarning(fmt.Sprintf("Nuclei terminó con error: %v", err))
		}
	}
	
	return nil
}

func (ns *NucleiScanner) updateStatsFromOutput(line string) {
	ns.stats.mu.Lock()
	defer ns.stats.mu.Unlock()
	
	// Buscar patrones en la salida para actualizar estadísticas
	if strings.Contains(line, "[critical]") {
		ns.stats.CriticalVulns++
		ns.stats.VulnsFound++
	} else if strings.Contains(line, "[high]") {
		ns.stats.HighVulns++
		ns.stats.VulnsFound++
	} else if strings.Contains(line, "[medium]") || strings.Contains(line, "[low]") || strings.Contains(line, "[info]") {
		ns.stats.VulnsFound++
	}
}

func (ns *NucleiScanner) analyzeResults() {
	printInfo("Analizando resultados...")
	
	// Archivos a verificar
	files := map[string]string{
		"nuclei_raw_output.txt": "Salida raw de nuclei",
		"nuclei_results.json":   "Resultados en formato JSON",
		"nuclei_report.md":      "Reporte en Markdown",
		"scan_log.txt":          "Log detallado del escaneo",
		"command.txt":           "Comando ejecutado",
		"targets_backup.txt":    "Copia de seguridad de targets",
	}
	
	for filename, description := range files {
		filePath := filepath.Join(ns.sessionDir, filename)
		if info, err := os.Stat(filePath); err == nil {
			printSuccess(fmt.Sprintf("%s: %.2f KB", description, float64(info.Size())/1024))
		} else {
			printWarning(fmt.Sprintf("Archivo no encontrado: %s", filename))
		}
	}
	
	// Análisis detallado del archivo JSON
	ns.analyzeJSONResults()
	
	// Generar resumen
	ns.generateSummary()
}

func (ns *NucleiScanner) analyzeJSONResults() {
	jsonPath := filepath.Join(ns.sessionDir, "nuclei_results.json")
	file, err := os.Open(jsonPath)
	if err != nil {
		printWarning("No se pudo abrir archivo JSON de resultados")
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	
	totalVulns := 0
	uniqueTemplates := make(map[string]bool)
	
	for scanner.Scan() {
		totalVulns++
		line := scanner.Text()
		
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			if severity, ok := result["info"].(map[string]interface{})["severity"].(string); ok {
				severityCounts[severity]++
			}
			
			if templateID, ok := result["template-id"].(string); ok {
				uniqueTemplates[templateID] = true
			}
		}
	}
	
	// Actualizar estadísticas finales
	ns.stats.mu.Lock()
	ns.stats.VulnsFound = totalVulns
	ns.stats.CriticalVulns = severityCounts["critical"]
	ns.stats.HighVulns = severityCounts["high"]
	ns.stats.TemplatesUsed = len(uniqueTemplates)
	ns.stats.mu.Unlock()
	
	if totalVulns > 0 {
		printSuccess(fmt.Sprintf("Total de vulnerabilidades encontradas: %d", totalVulns))
		for severity, count := range severityCounts {
			if count > 0 {
				color := ColorWhite
				switch severity {
				case "critical":
					color = ColorRed
				case "high":
					color = ColorYellow
				case "medium":
					color = ColorBlue
				}
				fmt.Printf("  %s%s: %d%s\n", color, strings.ToUpper(severity), count, ColorReset)
			}
		}
		printInfo(fmt.Sprintf("Templates únicos utilizados: %d", len(uniqueTemplates)))
	} else {
		printInfo("No se encontraron vulnerabilidades")
	}
}

func (ns *NucleiScanner) generateSummary() {
	summaryPath := filepath.Join(ns.sessionDir, "scan_summary.txt")
	file, err := os.Create(summaryPath)
	if err != nil {
		printWarning("No se pudo crear archivo de resumen")
		return
	}
	defer file.Close()
	
	duration := ns.stats.EndTime.Sub(ns.stats.StartTime)
	
	summary := fmt.Sprintf(`
=== RESUMEN DEL ESCANEO NUCLEI ===
Fecha: %s
Duración: %v

=== CONFIGURACIÓN ===
Archivo de targets: %s
Concurrencia: %d
Rate Limit: %d
Timeout: %d segundos
Reintentos: %d
Severidades: %s
Tags: %s

=== ESTADÍSTICAS ===
Total de targets: %d
Vulnerabilidades encontradas: %d
Vulnerabilidades críticas: %d
Vulnerabilidades altas: %d
Templates utilizados: %d
Errores: %d

=== ARCHIVOS GENERADOS ===
- nuclei_raw_output.txt
- nuclei_results.json
- nuclei_report.md
- scan_log.txt
- command.txt
- targets_backup.txt
- scan_summary.txt

=== DIRECTORIO DE RESULTADOS ===
%s
`,
		ns.stats.StartTime.Format("2006-01-02 15:04:05"),
		duration,
		ns.config.TargetsFile,
		ns.config.Concurrency,
		ns.config.RateLimit,
		ns.config.Timeout,
		ns.config.Retries,
		strings.Join(ns.config.Severity, ","),
		strings.Join(ns.config.Tags, ","),
		ns.stats.TotalTargets,
		ns.stats.VulnsFound,
		ns.stats.CriticalVulns,
		ns.stats.HighVulns,
		ns.stats.TemplatesUsed,
		ns.stats.Errors,
		ns.sessionDir,
	)
	
	file.WriteString(summary)
	printSuccess("Resumen generado: scan_summary.txt")
}

func (ns *NucleiScanner) setupSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-c
		printWarning("Señal de interrupción recibida, terminando escaneo...")
		ns.cancel()
	}()
}

func (ns *NucleiScanner) Run() error {
	printBanner()
	
	// Configurar manejo de señales
	ns.setupSignalHandling()
	
	// Verificar dependencias
	if err := ns.checkDependencies(); err != nil {
		return fmt.Errorf("error en dependencias: %v", err)
	}
	
	// Validar archivo de objetivos
	targets, err := ns.validateTargetsFile()
	if err != nil {
		return fmt.Errorf("error validando objetivos: %v", err)
	}
	
	// Mostrar objetivos
	printInfo("Objetivos a escanear:")
	for i, target := range targets {
		if i < 10 { // Mostrar solo los primeros 10
			fmt.Printf("  %d. %s\n", i+1, target)
		}
	}
	if len(targets) > 10 {
		fmt.Printf("  ... y %d más\n", len(targets)-10)
	}
	
	// Crear directorio de sesión
	if err := ns.createSessionDirectory(targets[0]); err != nil {
		return err
	}
	
	// Copiar archivo de objetivos
	targetsBackup := filepath.Join(ns.sessionDir, "targets_backup.txt")
	if err := ns.copyFile(ns.config.TargetsFile, targetsBackup); err != nil {
		printWarning(fmt.Sprintf("No se pudo copiar archivo de objetivos: %v", err))
	} else {
		printSuccess("Archivo de objetivos copiado")
	}
	
	// Ejecutar escaneo
	printInfo("Iniciando escaneo con Nuclei...")
	if err := ns.runScan(); err != nil {
		return fmt.Errorf("error durante escaneo: %v", err)
	}
	
	// Calcular duración
	duration := ns.stats.EndTime.Sub(ns.stats.StartTime)
	printSuccess(fmt.Sprintf("Escaneo completado en %v", duration))
	
	// Analizar resultados
	ns.analyzeResults()
	
	// Mostrar resumen final
	ns.printFinalSummary()
	
	return nil
}

func (ns *NucleiScanner) printFinalSummary() {
	fmt.Printf("\n%s%s=== RESUMEN FINAL ===%s\n", ColorCyan, ColorBold, ColorReset)
	
	duration := ns.stats.EndTime.Sub(ns.stats.StartTime)
	
	fmt.Printf("⏱️  Duración total: %v\n", duration)
	fmt.Printf("🎯 Targets escaneados: %d\n", ns.stats.TotalTargets)
	fmt.Printf("🔍 Vulnerabilidades encontradas: %d\n", ns.stats.VulnsFound)
	
	if ns.stats.CriticalVulns > 0 {
		fmt.Printf("🚨 Vulnerabilidades críticas: %s%d%s\n", ColorRed, ns.stats.CriticalVulns, ColorReset)
	}
	if ns.stats.HighVulns > 0 {
		fmt.Printf("⚠️  Vulnerabilidades altas: %s%d%s\n", ColorYellow, ns.stats.HighVulns, ColorReset)
	}
	
	fmt.Printf("📁 Directorio de resultados: %s%s%s\n", ColorCyan, ns.sessionDir, ColorReset)
	
	printInfo("Archivos generados:")
	fmt.Println("  📄 nuclei_raw_output.txt (salida raw)")
	fmt.Println("  📊 nuclei_results.json (resultados estructurados)")
	fmt.Println("  📝 nuclei_report.md (reporte markdown)")
	fmt.Println("  📋 scan_log.txt (log detallado)")
	fmt.Println("  ⚙️  command.txt (comando ejecutado)")
	fmt.Println("  💾 targets_backup.txt (copia de objetivos)")
	fmt.Println("  📈 scan_summary.txt (resumen del escaneo)")
	fmt.Println("  🗂️  nuclei-project/ (datos del proyecto)")
}

func main() {
	// Cargar configuración
	config, err := loadConfig("")
	if err != nil {
		printError(fmt.Sprintf("Error cargando configuración: %v", err))
		os.Exit(1)
	}
	
	// Crear y ejecutar scanner
	scanner := NewNucleiScanner(config)
	
	if err := scanner.Run(); err != nil {
		printError(fmt.Sprintf("Error ejecutando scanner: %v", err))
		os.Exit(1)
	}
	
	printSuccess("¡Escaneo completado exitosamente!")
}
