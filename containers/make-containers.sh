#!/bin/bash
#
sudo docker build -t docker.io/isilincoln/upf:latest -f Dockerfile.base .
sudo docker push docker.io/isilincoln/upf:latest 
