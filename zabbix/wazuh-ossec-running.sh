#!/bin/bash

process=`netstat -tulpn | grep 0.0.0.0:1514 | grep tcp | grep wazuh-remoted`
if [ $? == 0 ]
then
echo Wazuh Listening
else
echo Not Listening
fi
