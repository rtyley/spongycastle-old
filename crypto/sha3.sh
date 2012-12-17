#!/bin/sh -x

CDIR=`pwd`
CPROOT="${CDIR}/build/artifacts/jdk1.5/"
CPEXT="${CPROOT}/jars"
TESTEXT="test/data"
SUFFIX="jdk15on-147"

if [ "$1" = "all" ]
then
	CLASS=org.bouncycastle.crypto.test.RegressionTest 
else
	CLASS=org.bouncycastle.crypto.test.SHA3DigestTest 
fi

#CP=${CPEXT}/bctest-${SUFFIX}.jar:${CPEXT}/bcprov-${SUFFIX}.jar:${CPEXT}/bcprov-ext-${SUFFIX}.jar
CP=${CPROOT}/lcrypto-jdk15on-147/classes/

java -cp "${CP}" -Dbc.test.data.home=${TESTEXT} ${CLASS}


