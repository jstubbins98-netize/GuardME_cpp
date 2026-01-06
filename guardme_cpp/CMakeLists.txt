cmake_minimum_required(VERSION 3.21)
project(GuardME VERSION 1.0.0 LANGUAGES CXX)

# Policies for modern CMake compatibility
if(POLICY CMP0144)
    cmake_policy(SET CMP0144 NEW)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# macOS Homebrew Qt6 path hint
if(APPLE)
    set(CMAKE_PREFIX_PATH "/opt/homebrew/opt/qt" ${CMAKE_PREFIX_PATH})
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets Network Core Gui Concurrent)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)

set(SOURCES
    src/main.cpp
    src/gui/mainwindow.cpp
    src/gui/dashboardtab.cpp
    src/gui/controlstab.cpp
    src/gui/toolstab.cpp
    src/gui/emailprotectiontab.cpp
    src/gui/alertstab.cpp
    src/gui/apistatustab.cpp
    src/gui/chatbotwidget.cpp
    src/core/configmanager.cpp
    src/core/logger.cpp
    src/security/urlanalyzer.cpp
    src/security/downloadmonitor.cpp
    src/security/virusscanner.cpp
    src/security/credentialvault.cpp
    src/security/whoisanalyzer.cpp
    src/security/sslanalyzer.cpp
    src/network/breachcheck.cpp
    src/network/httpclient.cpp
    src/network/imapclient.cpp
    src/utils/systemmonitor.cpp
    src/ml/threatdetector.cpp
)

set(HEADERS
    include/gui/mainwindow.h
    include/gui/dashboardtab.h
    include/gui/controlstab.h
    include/gui/toolstab.h
    include/gui/emailprotectiontab.h
    include/gui/alertstab.h
    include/gui/apistatustab.h
    include/gui/chatbotwidget.h
    include/core/configmanager.h
    include/core/logger.h
    include/security/urlanalyzer.h
    include/security/downloadmonitor.h
    include/security/virusscanner.h
    include/security/credentialvault.h
    include/security/whoisanalyzer.h
    include/security/sslanalyzer.h
    include/network/breachcheck.h
    include/network/httpclient.h
    include/network/imapclient.h
    include/utils/systemmonitor.h
    include/ml/threatdetector.h
)

set(RESOURCES
    resources/resources.qrc
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS} ${RESOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt6::Widgets
    Qt6::Network
    Qt6::Core
    Qt6::Gui
    Qt6::Concurrent
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    nlohmann_json::nlohmann_json
)

file(COPY ${CMAKE_SOURCE_DIR}/resources DESTINATION ${CMAKE_BINARY_DIR})
