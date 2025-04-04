#!/bin/bash
set -e

LOG_FILE="/var/log/dns_query.log"
CONF="/etc/bind/named.conf.options"

sudo touch $LOG_FILE
sudo chown bind:bind $LOG_FILE
sudo chmod 644 $LOG_FILE

if ! grep -q "querylog yes" "$CONF"; then
    sudo sed -i '/options {/a \	querylog yes;' $CONF
fi

if ! grep -q "query_logging" "$CONF"; then
    cat <<EOF | sudo tee -a $CONF

logging {
    channel query_logging {
        file "/var/log/dns_query.log";
        severity info;
        print-time yes;
    };
    category queries { query_logging; };
};
EOF
fi

sudo systemctl restart bind9
