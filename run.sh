#!/bin/bash

# 以下三个固件解包目录下，都有/usr/lib/lua目录。
Modem_Root=/home/ubuntu/AP_Tasks/_Modem_firmware_5.8.5.bin.extracted/squashfs-root
TAU_Root=/home/ubuntu/AP_Tasks/_TAU-1.0.0.bin.extracted/squashfs-root
TAU_Device_Root=/home/ubuntu/AP_Tasks/TAU-usr-lib-lua

# python3 __main__.py -pr $Modem_Root/usr/lib/lua --dont-prepend-root --json -o Modem-vulns.json $Modem_Root
# python3 __main__.py -pr $TAU_Root/usr/lib/lua --dont-prepend-root --json -o TAU-vulns.json $TAU_Root
python3 __main__.py -pr $TAU_Device_Root/usr/lib/lua --dont-prepend-root --json -o TAU_Device-vulns.json $TAU_Device_Root


# 示例
# python3 __main__.py -pr ./squashfs-root/usr/lib/lua/ --dont-prepend-root --json -o vulns1.json ./squashfs-root/
