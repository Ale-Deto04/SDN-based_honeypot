#!/bin/bash

while [[ ! -f /shared/controller.ready ]]; do
	sleep 1
done

ping -c 1 "$GATEWAY"

echo "$(date +"%Y-%m-%d %T") [INFO]: system ready"