cmake_minimum_required(VERSION 3.10)

set(CMAKE_TOOLCHAIN_FILE $ENV{PSPDEV}/psp/share/pspdev.cmake)

project(64kformat)

include_directories(libs psptool_source/include)
link_directories(libs)
add_definitions(-Os -G0 -Wall)


add_executable(64kformat main.c hwdetect.c)
target_link_libraries(64kformat pspsdk pspctrl pspge pspdisplay pspdebug pspexploit)

create_pbp_file(
    TARGET 64kformat
    TITLE "64kformat"
    ICON_PATH NULL
    BACKGROUND_PATH NULL
    PREVIEW_PATH NULL
    BGM_PATH NULL
)
