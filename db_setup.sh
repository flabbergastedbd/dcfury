#!/usr/bin/env sh
if [ "$1" = "" ]
then
    echo "Usage: $0 [action]"
    echo
    echo "[*] To create database and user"
    echo "./$0 \"init\""
    echo
    echo "[*] To remove database and user"
    echo "./$0 \"clean\""
    exit 1
fi

# Bail out if not root privileges
# if [ "$(id -u)" != "0" ]; then
#   echo "This script must be run as root" 1>&2
#   exit 1
#fi

Action=$1

db_name="dcfury"
db_user="root"
db_pass="shadow"

if [ "$Action" = "init" ]
then
    psql template1 -c "DROP DATABASE $db_name"
    psql template1 -c "DROP USER $db_user"
    psql template1 -c "CREATE USER $db_user WITH PASSWORD '$db_pass'"
    psql template1 -c "CREATE DATABASE $db_name WITH OWNER $db_user ENCODING 'UTF-8';"
elif [ "$Action" = "clean" ]
then
    psql template1 -c "DROP DATABASE $db_name"
    psql template1 -c "DROP USER $db_user"
fi
