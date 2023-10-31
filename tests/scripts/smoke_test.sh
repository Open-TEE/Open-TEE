#!/bin/bash

#kill existing manager process
pkill -9 tee_manager

#launch manager
./../../../project-build/qtc_Desktop-debug/TEE_Core_Process

for i in {1..5}
do

 #Connection to keep_alive_ta
 xterm -e 'for j in {1..500}; do ./../../../project-build/qtc_Desktop-debug/conn_without_param_ca a; echo $j; done' &
 
 #connection to keep_alive_ta_random
 xterm -e 'for j in {1..500}; do ./../../../project-build/qtc_Desktop-debug/conn_without_param_ca b; echo $j; done' &
 
 #connection to signeleton_ta
 xterm -e 'for j in {1..500}; do ./../../../project-build/qtc_Desktop-debug/conn_without_param_ca c; echo $j; done' &
 
 #connection to signeleton_ta_random
 xterm -e 'for j in {1..500}; do ./../../../project-build/qtc_Desktop-debug/conn_without_param_ca d; echo $j; done' &
 
done