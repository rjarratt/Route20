#!/bin/sh
# Rename this file "route20" and place it in the /usr/local/etc/rc.d directory. Give it +x permissions.
# Add route20_enable to /etc/rc.conf, use sysrc route20_enable="YES"

# PROVIDE: route20
# REQUIRE: networking syslog
# KEYWORD: shutdown

. /etc/rc.subr

name=route20
rcvar=route20_enable

command="/root/route20/${name}" # Modify this for where you keep your binary
command_args="/root/route20/${name}.ini" # Modify this for where you keep the configuration

pidfile="/var/run/${name}.pid"
extra_commands=reload

load_rc_config $name
run_rc_command "$1"
