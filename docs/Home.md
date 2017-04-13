# What Is It?
This program is a DECnet router that implements version 2.0 of the DECnet routing specification
found here: http://linux-decnet.sourceforge.net/docs/route20.txt

# Second Alpha Release 15th Sep 2012
This second release has been successfully tested with another person in another area. It
fixes the following bugs and limitations:

# Implements Level 1 Routing messages and interoperates correctly with Level 1 routers (ie routing nodes that are not area routers).
# Packets routed from outside into the local area are no longer dropped.
# More tolerant of different line end formats on the configuration file (ie DOS or non-DOS format).
# Fixed some compiler warnings related to format strings.
I have also realised that for every bridge connection you use you need a separate UDP port.
I am not sure if this is a flaw or a feature.

# Features
# Runs on Windows either as a Windows Service, or as a console program.
# Runs on Linux as a daemon.
# Full routing capability, so it avoids broadcasting all routing messages to entire network and kills looping packets.
# Supports Ethernet (using pcap/winpcap).
# Supports Johnny's bridge. You can now have multiple bridge connections to Johnny and direct to other people without creating loops.
# Can be extended to support other kinds of circuit (Cisco and Multinet might be examples, not tried).
# Does dynamic DNS updates without blocking.

# Limitations
# Only tested on Windows Server 2003 and Raspberry Pi running Debian.
# Does not support Phase III nodes.
# Although it can be configured as a Level 1 node, it has only been tested as a Level 2 (area router) node.
# Limited testing on Raspberry Pi.
# Performance not tested. Does not implement throttling, so traffic sent to a machine with a slow network interface may experience problems.
# Not tested with multiple ethernets.
# It does not handle LAT and MOP, if you need these protocols then you still need to use Johnny's bridge.

# Configuration

The program expects a configuration file called route20.ini. A sample is provided, but here are some notes.

An {"[ethernet](ethernet)(ethernet)"} section is used to define an Ethernet network interface. You can have as many {"[ethernet](ethernet)(ethernet)"} sections as you have ethernet network interfaces.

A {"[bridge](bridge)(bridge)"} section is used to define an interface compatible with Johnny's bridge. You can have as many {"[bridge](bridge)(bridge)"} sections as you have direct links to other people's bridge or router (each requires a separate port). Use a DNS name rather than an IP address, the IP address is checked and updated according the {"[dns](dns)"} section. Note also that the router will not accept packets from bridges not configured in the 
{"[bridge](bridge)"} section.

The {"[dns](dns)"} section is used to specify the IP address of your DNS server. This must be a numeric IP address. The poll period determines the period (in seconds) of the checks for changes to the IP address in your {"[bridge](bridge)"} sections.

# Windows Installation

Prerequisites: winpcap

## To install it as a service do the following:

# Open a command prompt as an administrator.
# Run "route20 install".
# Copy the configuration file to %windir%\system32
# Make sure the "DECnet 2.0 Router" service is configured to run under an account that has administrative privileges.
# Start the service.

## To run it as a console program:

# Create a configuration file in the directory where the executable is located.
# Run the executable.

## Linux Installation

Prerequisites: pcap

The program is designed to run only as a daemon. It logs to the syslog.
Launch the program and it will fork and create a daemon.
