#!/usr/bin/env bash
modify_file() {
	read -p "$p: ($default) " newval
	if [ ! -z "$newval" ]; then
		echo "Changing $default to $newval in $file..."
		sed -i "s/$default/$newval/g" $file
		if [ ! -z "$file_2" ]; then
			echo "Changing $default to $newval in $file_2..."
			sed -i "s/$default/$newval/g" $file
			unset file_2
		fi
		unset newval
	else
		echo "Keeping default setting $default in $file $file_2"
	fi
}
parameter="server_ip port magic thread_name icmp_sequence pattern_1 pattern_2 pattern_3 pattern_4 pattern_5"
for p in $parameter; do
	case $p in
		server_ip)
			default="127.0.0.1"
			file="include/core.h"
			;;
		port)
			default="8081"
			file="modules/hiding_tcp.c"
			file_2="modules/icmp.c"
			;;
		magic)
			default="mtz"
			file="modules/become_root.c"
			;;
		thread_name)
			default="zer0t"
			file="modules/reset_tainted.c"
			;;
		icmp_sequence)
			default="1337"
			file="modules/icmp.c"
			file_2="scripts/trigger.py"
			;;
		pattern_1)
			default="jira"
			file="include/hiding_directory_def.h"
			;;
		pattern_2)
			default="singularity"
			file="include/hiding_directory_def.h"
			;;
		pattern_3)
			default="obliviate"
			file="include/hiding_directory_def.h"
			;;
		pattern_4)
			default="matheuz"
			file="include/hiding_directory_def.h"
			;;
		pattern_5)
			default="zer0t"
			file="include/hiding_directory_def.h"
			;;
	esac
	modify_file
done
