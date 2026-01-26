# virtualdisplay-qt - Trusted User Interface Virtual Display - Qt edition
# CMakeLists.txt
#
# SPDX-FileCopyRightText: 2026 Mika Tammi
# SPDX-License-Identifier: Apache-2.0

# ============================================================================
# Executable: virtualdisplay-qt
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(msgpack-cxx REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

qt_standard_project_setup()

qt_add_executable(virtualdisplay-qt
    comprotocolmessage.cpp
    comprotocolsocket.cpp
    main.cpp
    mainwindow.cpp
    mainwindow.ui
    settingsdialog.cpp
    settingsdialog.ui
    trusteduiwidget.cpp
    tuiprotocol.cpp
    tuiservice.cpp
    tuistate.cpp
)

# Public include directory (for consumers of this library)
target_include_directories(virtualdisplay-qt
    PRIVATE
        ${CMAKE_SOURCE_DIR}/msgpack-c/include
)

# Link dependencies
target_link_libraries(virtualdisplay-qt
    PRIVATE
        tee
        ZLIB::ZLIB
        msgpack-cxx
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS virtualdisplay-qt
    EXPORT OpenTEETargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
