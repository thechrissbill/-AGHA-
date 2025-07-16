cmake_minimum_required(VERSION 3.10)
project(NucleiAutomation)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Encontrar nlohmann_json
include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
)
FetchContent_MakeAvailable(json)

add_executable(nuclei_scanner src/nuclei_scanner.cpp)
target_link_libraries(nuclei_scanner PRIVATE nlohmann_json::nlohmann_json)
