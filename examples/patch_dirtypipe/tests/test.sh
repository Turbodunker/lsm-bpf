#!/bin/bash

INPUT_FILE="randomFile"
DUMP_WRITE="dummyFile"
DUMP_READ="readme"


echo "Creating files for benchmark test"
head -c 3G < /dev/urandom > $INPUT_FILE
head -c 1G < /dev/urandom > $DUMP_READ
touch $DUMP_WRITE

echo "Starting benchmark using perf"
perf stat -r 100 ./bench $INPUT_FILE $DUMP_WRITE


echo "Cleaning up.."
rm $INPUT_FILE
rm $DUMP_WRITE
rm $DUMP_READ

