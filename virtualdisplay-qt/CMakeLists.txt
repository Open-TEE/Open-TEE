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
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Test)

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
# Executable: test_comprotocolmessage
# ============================================================================

qt_add_executable(test_comprotocolmessage
    tests/test_comprotocolmessage.cpp
    comprotocolmessage.cpp
)

# Link dependencies
target_link_libraries(test_comprotocolmessage
    PRIVATE
        tee
        Qt6::Test
)

# ============================================================================
# Executable: test_tuiprotocol
# ============================================================================

qt_add_executable(test_tuiprotocol
    tests/test_tuiprotocol.cpp
    tuiprotocol.cpp
)

# Link dependencies
target_link_libraries(test_tuiprotocol
    PRIVATE
        msgpack-cxx
        tee
        Qt6::Test
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS virtualdisplay-qt
    EXPORT OpenTEETargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(TARGETS test_comprotocolmessage
    EXPORT OpenTEETargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(TARGETS test_tuiprotocol
    EXPORT OpenTEETargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
