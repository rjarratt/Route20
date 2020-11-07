# What Is It?
This program is a DECnet router that implements version 2.0 of the DECnet routing specification
found here: http://linux-decnet.sourceforge.net/docs/route20.txt

# Fourth Alpha Release <unreleased>

Minor changes:
1. Improved management of NSP connections.
1. Added support for the SHOW EXECUTOR CHARACTERISTICS network management command.
1. Added support for the SHOW KNOWN CIRCUIT STATUS network management command.
1. Improved internal representation of adjacencies to minimise searching.
1. On Unix flavours it now creates a PID file in /var/run.
1. On Unix flavours it now re-reads parts of the configuration on receiving a kill -s HUP.
1. Miscellanous bug fixes.

# Third Alpha Release 10th October 2020
This third release has the following major new Features
1. Basic Network Management commands with support for the following commands:
   * SHOW KNOWN CIRCUITS
   * SHOW ADJACENT NODES
1. DDCMP over TCP/IP
   * There are the beginnings of some Phase II support, which has been partially tested against TOPS-20 on SimH. Maintenance mode is not supported
1. A partially completed port to VAXELN.

More minor changes include:
1. Now also runs on FreeBSD.
1. Added a requirement for the router node to be named. This is needed particularly for Phase II.
1. Windows logging will log to console as well if it is being run interactively.
1. Lots of bug fixes and minor improvements.

# Second Alpha Release 15th Sep 2012
This second release has been successfully tested with another person in another area. It
fixes the following bugs and limitations:

1. Implements Level 1 Routing messages and interoperates correctly with Level 1 routers (ie routing nodes that are not area routers).
1. Packets routed from outside into the local area are no longer dropped.
1. More tolerant of different line end formats on the configuration file (ie DOS or non-DOS format).
1. Fixed some compiler warnings related to format strings.
I have also realised that for every bridge connection you use you need a separate UDP port.
I am not sure if this is a flaw or a feature.

1. Features
1. Runs on Windows either as a Windows Service, or as a console program.
1. Runs on Linux and FreeBSD as a daemon.
1. Full routing capability, so it avoids broadcasting all routing messages to entire network and kills looping packets.
1. Supports Ethernet (using pcap/winpcap).
1. Supports Johnny's bridge. You can now have multiple bridge connections to Johnny and direct to other people without creating loops.
1. Can be extended to support other kinds of circuit (Cisco and Multinet might be examples, not tried).
1. Does dynamic DNS updates without blocking.

# Limitations
1. Only tested on Windows Server 2003, Raspberry Pi running Debian and FreeBSD.
1. Does not support Phase III nodes.
1. Although it can be configured as a Level 1 node, it has only been tested as a Level 2 (area router) node.
1. Limited testing on Raspberry Pi.
1. Performance not tested. Does not implement throttling, so traffic sent to a machine with a slow network interface may experience problems.
1. Not tested with multiple ethernets.
1. It does not handle LAT and MOP, if you need these protocols then you still need to use Johnny's bridge.

# Configuration

The program expects a configuration file called route20.ini. A sample is provided, but here are some notes.

An \[ethernet\] section is used to define an Ethernet network interface. You can have as many \[ethernet\] sections as you have ethernet network interfaces.

A \[bridge\] section is used to define an interface compatible with Johnny's bridge. You can have as many \[bridge\] sections as you have direct links to other people's bridge or router (each requires a separate port). Use a DNS name rather than an IP address, the IP address is checked and updated according the \[dns\] section. Note also that the router will not accept packets from bridges not configured in the 
\[bridge\] section.

The \[dns\] section is used to specify the IP address of your DNS server. This must be a numeric IP address. The poll period determines the period (in seconds) of the checks for changes to the IP address in your \[bridge\] sections.

# Windows Installation

Prerequisites: winpcap

## To install it as a service do the following:

1. Open a command prompt as an administrator.
1. Run "route20 install".
1. Copy the configuration file to %windir%\system32
1. Make sure the "DECnet 2.0 Router" service is configured to run under an account that has administrative privileges.
1. Start the service.

## To run it as a console program:

1. Create a configuration file in the directory where the executable is located.
1. Run the executable.

## Linux Installation

Prerequisites: pcap

The program is designed to run only as a daemon. It logs to the syslog.
Launch the program and it will fork and create a daemon. Using kill -s HUP will cause parts of the configuration to be re-read.
