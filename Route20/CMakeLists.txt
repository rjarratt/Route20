add_executable(Route20)
target_sources(Route20
    PRIVATE
    	Route20.c
        route20.ini
    	adjacency.c
    	area_forwarding_database.c
    	area_routing_database.c
    	circuit.c
    	ddcmp.c
    	ddcmp_circuit.c
    	ddcmp_init_layer.c
    	ddcmp_sock_line.c
    	decision.c
    	decnet.c
    	dns.c
    	eth_circuit.c
    	eth_decnet.c
    	eth_init_layer.c
    	eth_pcap_line.c
    	eth_sock_line.c
    	forwarding.c
    	forwarding_database.c
    	init_layer.c
    	line.c
    	linux.c
    	logging.c
    	messages.c
    	netman.c
    	netman_messages.c
    	node.c
    	nsp.c
    	nsp_messages.c
    	nsp_session_control_port_database.c
    	nsp_transmit_queue.c
    	packet.c
    	route20.rc.d
    	routing_database.c
        session.c
        socket.c
        timer.c
        update.c
        vaxeln.c
        windows.c
        FindNpcap.cmake
    PRIVATE
	FILE_SET headers
	TYPE HEADERS
	FILES
    	Route20.h
    	adjacency.h
    	area_forwarding_database.h
    	area_routing_database.h
    	basictypes.h
    	circuit.h
    	constants.h
    	ddcmp.h
    	ddcmp_circuit.h
    	ddcmp_init_layer.h
    	ddcmp_sock_line.h
    	decision.h
    	decnet.h
    	dns.h
    	eth_circuit.h
    	eth_decnet.h
    	eth_init_layer.h
    	eth_pcap_line.h
    	eth_sock_line.h
    	forwarding.h
    	forwarding_database.h
    	init_layer.h
    	line.h
    	logging.h
    	messages.h
    	netman.h
    	netman_messages.h
    	node.h
    	nsp.h
    	nsp_messages.h
    	nsp_session_control_port_database.h
    	nsp_transmit_queue.h
    	packet.h
    	route20.rc.d
    	routing_database.h
        session.h
        socket.h
        timer.h
        update.h
)
set_source_files_properties(route20.ini PROPERTIES HEADER_FILE_ONLY ON)
set_source_files_properties(FindNpcap.cmake PROPERTIES HEADER_FILE_ONLY ON)
find_package(Npcap REQUIRED)
target_include_directories(Route20 PRIVATE ${NPCAP_INCLUDE_DIR})
target_link_directories(Route20 PRIVATE ${NPCAP_LIBRARY_DIR})
target_link_libraries(Route20 PRIVATE dbghelp.lib wsock32.lib ws2_32.lib wpcap.lib Packet.lib)
if (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    set_property(DIRECTORY .. PROPERTY VS_STARTUP_PROJECT Route20)
    add_compile_definitions(Route20 PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(Route20 PRIVATE /WX- /Wall /wd4100 /wd4200 /wd4127 /wd4206 /wd4706 /wd5045 /external:W1)
    add_custom_command(
        TARGET Route20
        POST_BUILD
        COMMAND copy "$(ProjectDir)..\\..\\Route20\\route20.ini" "$(ProjectDir)"
    )
endif ()