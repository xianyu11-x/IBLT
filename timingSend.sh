#!/bin/sh


for file in `ls ./pt*_copy.pcap`
do
        tcpreplay -i p5p2 -t ${file}
        sleep $1
done
