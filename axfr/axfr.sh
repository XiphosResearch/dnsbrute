#!/bin/sh

# script by Hanno Böck, license CC0 / public domain
#
# Usage:
#  ./axfr.sh [csv]
#
# csv should be a file in the format of the Alexa 1 million database:
# [number],[domain]

mkdir -p out

tmp=$(mktemp -d)

for dd in `cat $1`; do

	d=$(echo $dd|sed -e 's:.*,::g')
	i=$(printf "%06d" `echo $dd|sed -e 's:,.*::g'`)
	echo $i $d

	ns=`dig +time=2 +tries=1 +short -t ns $d`

	for n in $ns; do
		echo checking $d $n
		dig +time=2 +tries=1 axfr $d @$n > $tmp/axfr
		grep "XFR" $tmp/axfr
		if [ $? -eq 0 ]; then
			echo + hit
			cp $tmp/axfr out/$i-$d-$n
		fi
	done
done

rm -rf $tmp
