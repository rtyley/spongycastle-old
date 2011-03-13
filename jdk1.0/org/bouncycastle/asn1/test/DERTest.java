package org.spongycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInputStream;
import org.spongycastle.asn1.DEROutputStream;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.RSAPublicKeyStructure;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.util.encoders.Hex;

public class DERTest
    implements PKCSObjectIdentifiers
{
    public static void main(
        String[]    args)
        throws IOException
    {
        BigInteger  one = BigInteger.valueOf(1);
        BigInteger  two = BigInteger.valueOf(2);
        BigInteger  three = BigInteger.valueOf(3);
        BigInteger  four = BigInteger.valueOf(4);
        BigInteger  five = BigInteger.valueOf(5);
        BigInteger  six = BigInteger.valueOf(6);
        BigInteger  seven = BigInteger.valueOf(7);
        BigInteger  eight = BigInteger.valueOf(8);

        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        RSAPrivateKeyStructure  priv = new RSAPrivateKeyStructure(one, two, three, four, five, six, seven, eight);
        PrivateKeyInfo          info = new PrivateKeyInfo(new AlgorithmIdentifier(rsaEncryption, null), priv.getDERObject());

        dOut.writeObject(info);
        dOut.close();

        byte[]  data = bOut.toByteArray();

        System.out.println(new String(Hex.encode(data), 0));

        ByteArrayInputStream    bIn = new ByteArrayInputStream(data);
        DERInputStream          dIn = new DERInputStream(bIn);

        info = new PrivateKeyInfo((ASN1Sequence)dIn.readObject());
        priv = new RSAPrivateKeyStructure((ASN1Sequence)info.getPrivateKey());

        System.out.println(
                    priv.getModulus() + " "
                    + priv.getPublicExponent() + " " 
                    + priv.getPrivateExponent() + " " 
                    + priv.getPrime1() + " " 
                    + priv.getPrime2() + " " 
                    + priv.getExponent1() + " " 
                    + priv.getExponent2() + " " 
                    + priv.getCoefficient());

        //
        // X509 public key
        //
        bOut = new ByteArrayOutputStream();
        dOut = new DEROutputStream(bOut);
        SubjectPublicKeyInfo          pubInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(rsaEncryption, null), new RSAPublicKeyStructure(one, two).getDERObject());

        dOut.writeObject(pubInfo);
        dOut.close();

        data = bOut.toByteArray();

        System.out.println(new String(Hex.encode(data), 0));

        bIn = new ByteArrayInputStream(data);
        dIn = new DERInputStream(bIn);

        pubInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());

        RSAPublicKeyStructure   pubKey = new RSAPublicKeyStructure((ASN1Sequence)pubInfo.getPublicKey());

        System.out.println(
                    pubKey.getModulus() + " "
                    + pubKey.getPublicExponent());
    }
}
