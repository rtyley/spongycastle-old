#!/bin/bash 

function move_file {
    mkdir -p `dirname $2`
    mv $1 $2
}

function move_files {
    echo Moving $1 to $2
    for FILENAME in `find $1 -type f -print`
    do
        move_file $FILENAME `echo $FILENAME | sed -e "s,$1,$2,"`
    done
}

function move_files_of_type {
    echo Moving $1 to $2 for files of type $3
    for FILENAME in `find $1 -type f -name "*.$3" -print`
    do
        move_file $FILENAME `echo $FILENAME | sed -e "s,$1,$2,"`
    done
}

function transplant_package {
    module=$1
    pkg=$2
    echo "mod = $module -- full package name = $pkg"
        
    for filetype in "java" "html"
    do
        move_files_of_type crypto/src/$pkg $module/src/main/java/$pkg $filetype
    done
    for filetype in "java" "html"
    do
        move_files_of_type crypto/test/src/$pkg $module/src/test/java/$pkg $filetype
    done
    move_files crypto/src/$pkg $module/src/main/resources/$pkg
    move_files crypto/test/src/$pkg $module/src/test/resources/$pkg    
    move_files crypto/test/data/$pkg $module/src/test/resources/$pkg
}

function transplant_packages {
    module=$1
    for package in ${@:2}
    do
        transplant_package $module org/bouncycastle/$package
    done
}

pushd $1

git reset --hard

git clean -f -f -d

transplant_packages bcmail-jdk15on {mail,cms/test}
transplant_packages bcpg-jdk15on {openpgp,bcpg}
transplant_packages bcpkix-jdk15on {cert,jce/provider/test,cms,eac,pkcs,mozilla,ocsp/test,operator,openssl,tsp,voms}
transplant_packages bcprov-jdk15on {i18n,jcajce,jce,ocsp,x509,pqc/jcajce}
transplant_package bc-light-jdk15on org/bouncycastle

move_files crypto/test/data/PKITS bcprov-jdk15on/src/test/resources/PKITS
move_files crypto/test/data/openpgp bcpg-jdk15on/src/test/resources/openpgp
move_files crypto/test/data/rfc4134 bcmail-jdk15on/src/test/resources/rfc4134

move_files crypto/bzip2/src bc-bzip2/src/main/java

mvn clean compile test-compile

popd

cp use-maven-layout.sh $1/


#                        crypto/test/src/org/bouncycastle/i18n/test/I18nTestMessages_en.properties
#           bcprov-jdk15on/src/test/java/org/bouncycastle/i18n/test/I18nTestMessages_en.properties -- initial copy
#      bcprov-jdk15on/src/test/resources/org/bouncycastle/i18n/test/I18nTestMessages_en.properties -- SHOULD BE
# bcprov-jdk15on/src/test/resources/java/org/bouncycastle/i18n/test/I18nTestMessages_en.properties -- NOT


#                    crypto/src/org/bouncycastle/x509/CertPathReviewerMessages.properties
#  bcprov-jdk15on/src/main/java/org/bouncycastle/x509/CertPathReviewerMessages.properties -- initial copy
# bcprov-jdk15on/src/main/resources/bouncycastle/x509/CertPathReviewerMessages.properties -- NOT

