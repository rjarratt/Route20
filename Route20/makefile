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
          decision.c \
          decnet.c \
          dns.c \
          eth_circuit.c \
          eth_decnet.c \
          eth_init_layer.c \
          eth_pcap.c \
          eth_sock.c \
          forwarding.c \
          forwarding_database.c \
          init_layer.c \
          linux.c \
          messages.c \
          node.c \
          packet.c \
          route20.c \
          routing_database.c \
          socket.c \
          timer.c \
          update.c

route20 : ${ROUTE20}
	${CC} ${ROUTE20} $(CC_OUTSPEC) ${LDFLAGS} -lpcap

