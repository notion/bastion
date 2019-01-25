#!/bin/bash

rm -rf build/
mkdir -p build/web
cp $(which bastion) build/bastion
find web/ -maxdepth 1 -mindepth 1 -type d -exec cp -R {} build/web \;
cp config.example.yml build/
tar -czvf bastion.tar.gz --directory ./build .
shasum bastion.tar.gz | tee bastion.tar.gz.sum