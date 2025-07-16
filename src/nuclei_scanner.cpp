#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>
#include <regex>
#include <nlohmann/json.hpp>
#include <map>
#include <array>
#include <algorithm>

using json = nlohmann::json;

struct ScanResult {
    std::string name;
    std::string severity;
    std::string template_id;
    std::string matched_at;
    std::string description;
    std::string timestamp;
};

class NucleiScanner {
private:
    std::string target;
    std::string templates_path;
    std::string output_dir;
    bool verbose;
    int timeout;
    int rate_limit;
    bool headless;
    std::vector<std::string> severity_filters;
    std::vector<std::string> tags;
    
    std::vector<ScanResult> parseResults(const std::string& file_path) {
        std::vector<ScanResult> results;
        std::ifstream file(file_path);
        std::string line;
        
        while (std::getline(file, line)) {
            if (line.empty()) continue;
            try {
                json j = json::parse(line);
                ScanResult result;
                result.name = j["info"]["name"].get<std::string>();
                result.severity = j["info"]["severity"].get<std::string>();
                result.template_id = j["template-id"].get<std::string>();
                result.matched_at = j["matched-at"].get<std::string>();
                result.description = j["info"]["description"].get<std::string>();
                result.timestamp = j["timestamp"].get<std::string>();
                
                // Aplicar filtros de severidad
                if (severity_filters.empty() || 
                    std::find(severity_filters.begin(), severity_filters.end(), 
                            result.severity) != severity_filters.end()) {
                    results.push_back(result);
                }
            } catch (const std::exception& e) {
                if (verbose) {
                    std::cerr << "Error al parsear línea: " << e.what() << "\n";
                }
            }
        }
        return results;
    }

    void generateReport(const std::vector<ScanResult>& results, 
                       const std::string& output_file) {
        std::ofstream report(output_file);
        report << "Reporte de Escaneo Nuclei\n";
        report << "========================\n\n";
        
        // Estadísticas
        std::map<std::string, int> severity_count;
        for (const auto& result : results) {
            severity_count[result.severity]++;
        }
        
        report << "Resumen:\n";
        report << "--------\n";
        for (const auto& [severity, count] : severity_count) {
            report << severity << ": " << count << " hallazgos\n";
        }
        report << "\nDetalles de los hallazgos:\n";
        report << "------------------------\n\n";
        
        for (const auto& result : results) {
            report << "Nombre: " << result.name << "\n";
            report << "Severidad: " << result.severity << "\n";
            report << "Template ID: " << result.template_id << "\n";
            report << "URL: " << result.matched_at << "\n";
            report << "Descripción: " << result.description << "\n";
            report << "Timestamp: " << result.timestamp << "\n";
            report << "------------------------\n\n";
        }
    }

    std::string exec(const std::string& cmd) {
        std::array<char, 4096> buffer;
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
        
        if (!pipe) {
            throw std::runtime_error("Error al ejecutar el comando: " + cmd);
        }
        
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        
        return result;
    }

public:
    NucleiScanner(const std::string& target = "", 
                  const std::string& templates = "nuclei-templates/",
                  const std::string& output = "nuclei_results/",
                  bool verbose = false,
                  int timeout = 5) 
        : target(target), templates_path(templates), output_dir(output),
          verbose(verbose), timeout(timeout), rate_limit(150), headless(false) {
        
        // Crear directorio de salida si no existe
        std::filesystem::create_directories(output_dir);
    }

    void setTarget(const std::string& new_target) {
        target = new_target;
    }

    void setTemplatesPath(const std::string& path) {
        templates_path = path;
    }

    void setRateLimit(int limit) {
        rate_limit = limit;
    }

    void setHeadless(bool enable) {
        headless = enable;
    }

    void addTags(const std::vector<std::string>& new_tags) {
        tags.insert(tags.end(), new_tags.begin(), new_tags.end());
    }

    void clearTags() {
        tags.clear();
    }

    bool checkNucleiInstallation() {
        try {
            std::string version = exec("nuclei -version");
            if (verbose) {
                std::cout << "Nuclei versión: " << version;
            }
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error: Nuclei no está instalado o no es accesible.\n";
            return false;
        }
    }

    bool updateTemplates() {
        try {
            std::string result = exec("nuclei -update-templates");
            if (verbose) {
                std::cout << "Actualización de templates: " << result;
            }
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error al actualizar templates: " << e.what() << "\n";
            return false;
        }
    }

    void setSeverityFilters(const std::vector<std::string>& severities) {
        severity_filters = severities;
    }

    std::pair<std::string, std::vector<ScanResult>> scan(bool update_before_scan = true) {
        if (target.empty()) {
            throw std::runtime_error("No se ha especificado un objetivo para escanear");
        }

        if (update_before_scan) {
            updateTemplates();
        }

        std::string timestamp = std::to_string(
            std::chrono::system_clock::now().time_since_epoch().count()
        );
        
        std::string output_file = output_dir + "scan_" + timestamp + ".json";
        std::string report_file = output_dir + "report_" + timestamp + ".txt";
        
        std::string cmd = "nuclei -u " + target + 
                         " -t " + templates_path + 
                         " -json -o " + output_file +
                         " -timeout " + std::to_string(timeout) +
                         " -rate-limit " + std::to_string(rate_limit);
        
        if (headless) {
            cmd += " -headless";
        }
        
        if (!tags.empty()) {
            cmd += " -tags ";
            for (const auto& tag : tags) {
                cmd += tag + ",";
            }
            cmd.pop_back(); // remove last comma
        }

        if (verbose) {
            std::cout << "Ejecutando: " << cmd << "\n";
        }

        try {
            exec(cmd);
            auto results = parseResults(output_file);
            generateReport(results, report_file);
            
            if (verbose) {
                std::cout << "Escaneo completado. JSON: " << output_file << "\n";
                std::cout << "Reporte generado: " << report_file << "\n";
            }
            
            return {output_file, results};
        } catch (const std::exception& e) {
            std::cerr << "Error durante el escaneo: " << e.what() << "\n";
            return {"", {}};
        }
    }

    std::vector<std::pair<std::string, std::vector<ScanResult>>> 
    batchScan(const std::vector<std::string>& targets) {
        std::vector<std::pair<std::string, std::vector<ScanResult>>> all_results;
        for (const auto& t : targets) {
            setTarget(t);
            auto result = scan(false);  // No actualizar templates en cada iteración
            if (!result.first.empty()) {
                all_results.push_back(result);
            }
        }
        return all_results;
    }
};

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            std::cerr << "Uso: " << argv[0] << " <url_objetivo> [urls_adicionales...]\n";
            return 1;
        }

        // Crear scanner con modo verbose
        NucleiScanner scanner("", "nuclei-templates/", "nuclei_results/", true);
        
        // Verificar instalación
        if (!scanner.checkNucleiInstallation()) {
            std::cerr << "Por favor, instala nuclei primero.\n";
            return 1;
        }

        // Configurar opciones
        scanner.setSeverityFilters({"critical", "high", "medium"});
        scanner.setRateLimit(100);  // Reducir la velocidad para evitar sobrecarga
        scanner.setHeadless(true);  // Usar modo headless para mejor rendimiento
        scanner.addTags({"cve", "rce", "sqli", "xss"});  // Buscar vulnerabilidades comunes
        
        // Escaneo individual del primer objetivo
        scanner.setTarget(argv[1]);
        auto [result_file, results] = scanner.scan();
        
        // Mostrar resultados del primer escaneo
        if (!results.empty()) {
            std::cout << "\nResultados del escaneo de " << argv[1] << ":\n";
            std::cout << "========================================\n";
            for (const auto& result : results) {
                std::cout << "\nVulnerabilidad: " << result.name << "\n";
                std::cout << "Severidad: " << result.severity << "\n";
                std::cout << "Template ID: " << result.template_id << "\n";
                std::cout << "URL: " << result.matched_at << "\n";
                std::cout << "\nDescripción:\n" << result.description << "\n";
                std::cout << "----------------------------------------\n";
            }
        } else {
            std::cout << "\nNo se encontraron vulnerabilidades en " << argv[1] << "\n";
        }
        
        // Si hay objetivos adicionales, hacer un escaneo por lotes
        if (argc > 2) {
            std::vector<std::string> additional_targets;
            for (int i = 2; i < argc; i++) {
                additional_targets.push_back(argv[i]);
            }
            
            std::cout << "\nIniciando escaneo por lotes de " << additional_targets.size() << " objetivos...\n";
            auto batch_results = scanner.batchScan(additional_targets);
            
            // Mostrar resultados del lote
            for (const auto& [file, scan_results] : batch_results) {
                if (!scan_results.empty()) {
                    std::cout << "\nResultados encontrados:\n";
                    for (const auto& result : scan_results) {
                        std::cout << "- " << result.name << 
                                   " (" << result.severity << ") en " << 
                                   result.matched_at << "\n";
                    }
                }
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
