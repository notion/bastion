#!/bin/bash

rm -rf build/
mkdir -p build/web
cp $(which bastion) build/bastion
cp -R web/templates build/web
cp config.example.yml build/
tar -czvf bastion.tar.gz --directory ./build .