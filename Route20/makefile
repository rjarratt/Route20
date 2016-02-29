CC_OUTSPEC = -o $@
CC = cc $(CFLAGS_G) $(CFLAGS_O) -I . $(OS_CCDEFS) $(ROMS_OPT)
LDFLAGS = $(OS_LDFLAGS) $(NETWORK_LDFLAGS) $(LDFLAGS_O)

#
# Common Libraries
#
ROUTE20 = adjacency.c \
          area_forwarding_database.c \
          area_routing_database.c \
          circuit.c \
          ddcmp.c \
          ddcmp_circuit.c \
          ddcmp_init_layer.c \
          ddcmp_sock_line.c \
          decision.c \
          decnet.c \
          dns.c \
          eth_circuit.c \
          eth_decnet.c \
          eth_init_layer.c \
          eth_pcap_line.c \
          eth_sock_line.c \
          forwarding.c \
          forwarding_database.c \
          init_layer.c \
          line.c \
          linux.c \
          logging.c \
          messages.c \
          netman.c \
          netman_messages.c \
          node.c \
          nsp.c \
          nsp_messages.c \
		  nsp_session_control_port_database.c \
		  nsp_transmit_queue.c \
          packet.c \
          route20.c \
          routing_database.c \
          socket.c \
          timer.c \
          update.c

route20 : ${ROUTE20}
	${CC} ${ROUTE20} $(CC_OUTSPEC) ${LDFLAGS} -lpcap

