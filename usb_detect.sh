#!/bin/bash

log_file="/var/log/usb_detect.json"
vendor="$ID_VENDOR"
model="$ID_MODEL"
serial="$ID_SERIAL_SHORT"
device="$DEVNAME"
devtype="$DEVTYPE"
hostname=$(hostname)

json="{\"hostname\":\"$hostname\",\"vendor\":\"$vendor\",\"model\":\"$model\",\"serial\":\"$serial\",\"device\":\"$device\",\"type\":\"$devtype\"}"

echo "$json" >> "$log_file"


