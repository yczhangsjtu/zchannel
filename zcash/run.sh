#!/bin/bash



if [ "$#" -lt "1" ]; then
	echo "Usage: $0 gen/js/dbg"
else
	if [ "$1" == "gen" ]; then
		echo "Saving pk vk r1cs to /tmp"
		LD_LIBRARY_PATH=`pwd`/secp256k1/.libs ./generate /tmp/pk /tmp/vk /tmp/r1cs
	fi
	
	if [ "$1" == "dbg" ]; then
		echo "Saving pk vk r1cs to /tmp"
		LD_LIBRARY_PATH=`pwd`/secp256k1/.libs gdb -q --args ./generate /tmp/pk /tmp/vk /tmp/r1cs
	fi

	if [ "$1" == "js" ]; then
		echo "Reading pk vk from /tmp"
		LD_LIBRARY_PATH=`pwd`/secp256k1/.libs ./createjs /tmp/pk /tmp/vk
	fi
fi
