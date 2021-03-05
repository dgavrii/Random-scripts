#!/bin/bash

echo -e ----------------------Collecting System Information-----------------
echo -e "Hostname:\t\t" `hostname`
echo -e "Uptime:\t\t\t" `uptime | awk '{print $3,$4}' | sed 's/,//'`
echo -e "Manufacturer:\t\t" `cat /sys/class/dmi/id/chassis_vendor`
echo -e "Product Name:\t\t" `cat /sys/class/dmi/id/product_name`
echo -e "Operating System:\t" `hostnamectl | grep "Operating System" | cut -d ' ' -f5-`
echo -e "Architecture:\t\t" `arch`
echo -e "Processor Name:\t\t" `awk -F':' '/model name/ {print $2}' /proc/cpuinfo | uniq | sed -e 's/^[ \t]*//'`
echo -e "Active User:\t\t" `w | cut -d ' ' -f1 | grep -v USER | xargs -n1`
echo -e "Host IP Address:\t" `hostname -I`
echo -e "IPv6:\t\t\t" `ip addr show dev eth0 | sed -e 's/^..*inet6 \([^ ]*\)\/.*$/\1/;t;d'`
