# FindNpcap.cmake

cmake_minimum_required(VERSION 3.31 FATAL_ERROR)

# Find the Npcap library
find_path(NPCAP_INCLUDE_DIR
    NAMES pcap.h
    PATHS
        ${NPCAP_ROOT}
        "$ENV{NPCAP_DIR}"
        "$ENV{ProgramFiles}/Npcap"
        "$ENV{ProgramFiles\(x86\)}/Npcap"
        /usr/local
        /usr
    PATH_SUFFIXES include
    REQUIRED
)
find_path(NPCAP_LIBRARY_DIR
    NAMES Packet.lib wpcap.lib
    PATHS
        ${NPCAP_ROOT}
        "$ENV{NPCAP_DIR}"
        "$ENV{ProgramFiles}/Npcap"
        "$ENV{ProgramFiles\(x86\)}/Npcap"
        /usr/local
        /usr
    PATH_SUFFIXES lib
    REQUIRED
)

mark_as_advanced(NPCAP_INCLUDE_DIR NPCAP_LIBRARY_DIR)
