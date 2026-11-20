#!/usr/bin/env bash
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
clear_color='\033[0m'
gen_random() {
	unset random_string
	random_string="$(tr -dc 0-9A-Za-z </dev/urandom | head -c 10; echo)"
}

modify_file() {
	if [[ "$dont_randomize" != 1 ]]; then
		gen_random
		unset default
		default="$random_string"
	fi
	printf "${green}$p${clear_color}: ${yellow}$default${clear_color}"
	read newval
	if [ ! -z "$newval" ]; then
		printf "Changing ${yellow}$default${clear_color} to ${red}$newval${clear_color} in $file"
		sed -i "s/$default/$newval/g" $file
		if [ ! -z "$file_2" ]; then
			printf " and $file_2..."
			sed -i "s/$default/$newval/g" $file
			unset file_2
		else
			printf "...\n"
		fi
		unset newval
	else
		printf "Keeping default ${green}$p${clear_color} ${yellow}$default ${clear_color}in $file $file_2\n"
	fi
}
printf "Modifying default values. Please enter a value for each parameter or hit ENTER to leave default\n"
parameter="server_ip port magic thread_name icmp_sequence pattern_1 pattern_2 pattern_3 pattern_4 pattern_5"
for p in $parameter; do
	case $p in
		server_ip)
			default="127.0.0.1"
			file="include/core.h"
			dont_randomize=1
			;;
		port)
			default="8081"
			file="modules/hiding_tcp.c"
			file_2="modules/icmp.c"
			dont_randomize=1
			;;
		magic)
			default="mtz"
			file="modules/become_root.c"
			dont_randomize=0
			;;
		thread_name)
			default="zer0t"
			file="modules/reset_tainted.c"
			dont_randomize=0
			;;
		icmp_sequence)
			default="1337"
			file="modules/icmp.c"
			file_2="scripts/trigger.py"
			dont_randomize=1
			;;
		pattern_1)
			default="jira"
			file="include/hiding_directory_def.h"
			dont_randomize=0
			;;
		pattern_2)
			default="singularity"
			file="include/hiding_directory_def.h"
			dont_randomize=0
			;;
		pattern_3)
			default="obliviate"
			file="include/hiding_directory_def.h"
			dont_randomize=0
			;;
		pattern_4)
			default="matheuz"
			file="include/hiding_directory_def.h"
			dont_randomize=0
			;;
		pattern_5)
			default="zer0t"
			file="include/hiding_directory_def.h"
			dont_randomize=0
			;;
	esac
	modify_file
done
