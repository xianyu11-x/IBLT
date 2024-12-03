#!/bin/sh
cd /root/tcpreplay/pcap/grpc
FILE=time.txt
if test -f "$FILE"; then
	echo "$FILE exist"
else 
	echo "$FILE does not exist"
	touch time.txt
fi

echo "$ 1 mirror"
echo "$ 2 grpc"


for file in `ls ../pt*_copy.pcap`
do
	

	if [ $1 = 2 ]; then
		echo $[$(date +%s%N)/1000-14400000000]   grpc >> time.txt 
	elif [ $1 = 1 ]; then 
		echo $[$(date +%s%N)/1000-14400000000]   mirror >> time.txt
	fi


	tcpreplay -i p5p2 -t ${file}
	sleep $2
done
