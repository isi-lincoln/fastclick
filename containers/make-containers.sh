#!/bin/bash
#
sudo docker build --build-arg CACHEBUST=`git rev-parse` -t docker.io/isilincoln/upf:latest -f Dockerfile.base .
sudo docker push docker.io/isilincoln/upf:latest 
