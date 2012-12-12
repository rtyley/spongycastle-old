#!/bin/sh -x

CDIR=`pwd`
CPEXT="${CDIR}/build/artifacts/jdk1.5/jars"
TESTEXT="test/data"
SUFFIX="jdk15on-147"
CLASS=org.bouncycastle.crypto.test.RegressionTest 

CP=${CPEXT}/bctest-${SUFFIX}.jar:${CPEXT}/bcprov-${SUFFIX}.jar:${CPEXT}/bcprov-ext-${SUFFIX}.jar
java -cp "${CP}" -Dbc.test.data.home=${TESTEXT} ${CLASS}


