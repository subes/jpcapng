#!/bin/sh

javac jpcap/*.java
jar cvf ../../lib/jpcap.jar jpcap/*.class
rm -rf jpcap/*.class
