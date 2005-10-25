package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPV3SignatureGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class PGPSignatureTest
    extends SimpleTest
{
    private static final int TEST_EXPIRATION_TIME = 10000;
    private static final String TEST_USER_ID = "test user id";
    private static final byte[] TEST_DATA = "hello world!\nhello world!\n".getBytes();
    private static final byte[] TEST_DATA_WITH_CRLF = "hello world!\r\nhello world!\r\n".getBytes();

    byte[] dsaKeyRing = Base64.decode(
          "lQHhBD9HBzURBACzkxRCVGJg5+Ld9DU4Xpnd4LCKgMq7YOY7Gi0EgK92gbaa6+zQ"
        + "oQFqz1tt3QUmpz3YVkm/zLESBBtC1ACIXGggUdFMUr5I87+1Cb6vzefAtGt8N5VV"
        + "1F/MXv1gJz4Bu6HyxL/ncfe71jsNhav0i4yAjf2etWFj53zK6R+Ojg5H6wCgpL9/"
        + "tXVfGP8SqFvyrN/437MlFSUEAIN3V6j/MUllyrZglrtr2+RWIwRrG/ACmrF6hTug"
        + "Ol4cQxaDYNcntXbhlTlJs9MxjTH3xxzylyirCyq7HzGJxZzSt6FTeh1DFYzhJ7Qu"
        + "YR1xrSdA6Y0mUv0ixD5A4nPHjupQ5QCqHGeRfFD/oHzD4zqBnJp/BJ3LvQ66bERJ"
        + "mKl5A/4uj3HoVxpb0vvyENfRqKMmGBISycY4MoH5uWfb23FffsT9r9KL6nJ4syLz"
        + "aRR0gvcbcjkc9Z3epI7gr3jTrb4d8WPxsDbT/W1tv9bG/EHawomLcihtuUU68Uej"
        + "6/wZot1XJqu2nQlku57+M/V2X1y26VKsipolPfja4uyBOOyvbP4DAwIDIBTxWjkC"
        + "GGAWQO2jy9CTvLHJEoTO7moHrp1FxOVpQ8iJHyRqZzLllO26OzgohbiPYz8u9qCu"
        + "lZ9Xn7QzRXJpYyBFY2hpZG5hIChEU0EgVGVzdCBLZXkpIDxlcmljQGJvdW5jeWNh"
        + "c3RsZS5vcmc+iFkEExECABkFAj9HBzUECwcDAgMVAgMDFgIBAh4BAheAAAoJEM0j"
        + "9enEyjRDAlwAnjTjjt57NKIgyym7OTCwzIU3xgFpAJ0VO5m5PfQKmGJRhaewLSZD"
        + "4nXkHg==");
    
    char[]    dsaPass = "hello world".toCharArray();

    byte[]    rsaKeyRing = Base64.decode(
          "lQIEBEBXUNMBBADScQczBibewnbCzCswc/9ut8R0fwlltBRxMW0NMdKJY2LF"
        + "7k2COeLOCIU95loJGV6ulbpDCXEO2Jyq8/qGw1qD3SCZNXxKs3GS8Iyh9Uwd"
        + "VL07nMMYl5NiQRsFB7wOb86+94tYWgvikVA5BRP5y3+O3GItnXnpWSJyREUy"
        + "6WI2QQAGKf4JAwIVmnRs4jtTX2DD05zy2mepEQ8bsqVAKIx7lEwvMVNcvg4Y"
        + "8vFLh9Mf/uNciwL4Se/ehfKQ/AT0JmBZduYMqRU2zhiBmxj4cXUQ0s36ysj7"
        + "fyDngGocDnM3cwPxaTF1ZRBQHSLewP7dqE7M73usFSz8vwD/0xNOHFRLKbsO"
        + "RqDlLA1Cg2Yd0wWPS0o7+qqk9ndqrjjSwMM8ftnzFGjShAdg4Ca7fFkcNePP"
        + "/rrwIH472FuRb7RbWzwXA4+4ZBdl8D4An0dwtfvAO+jCZSrLjmSpxEOveJxY"
        + "GduyR4IA4lemvAG51YHTHd4NXheuEqsIkn1yarwaaj47lFPnxNOElOREMdZb"
        + "nkWQb1jfgqO24imEZgrLMkK9bJfoDnlF4k6r6hZOp5FSFvc5kJB4cVo1QJl4"
        + "pwCSdoU6luwCggrlZhDnkGCSuQUUW45NE7Br22NGqn4/gHs0KCsWbAezApGj"
        + "qYUCfX1bcpPzUMzUlBaD5rz2vPeO58CDtBJ0ZXN0ZXIgPHRlc3RAdGVzdD6I"
        + "sgQTAQIAHAUCQFdQ0wIbAwQLBwMCAxUCAwMWAgECHgECF4AACgkQs8JyyQfH"
        + "97I1QgP8Cd+35maM2cbWV9iVRO+c5456KDi3oIUSNdPf1NQrCAtJqEUhmMSt"
        + "QbdiaFEkPrORISI/2htXruYn0aIpkCfbUheHOu0sef7s6pHmI2kOQPzR+C/j"
        + "8D9QvWsPOOso81KU2axUY8zIer64Uzqc4szMIlLw06c8vea27RfgjBpSCryw"
        + "AgAA");

    char[]    rsaPass = "2002 Buffalo Sabres".toCharArray();

    public void performTest()
        throws Exception
    {
        //
        // RSA tests
        //
        PGPSecretKeyRing pgpPriv = new PGPSecretKeyRing(rsaKeyRing);         
        PGPSecretKey secretKey = pgpPriv.getSecretKey();        
        PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(rsaPass, "BC");

        try
        {
            testSig(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);

            fail("RSA wrong key test failed.");
        }
        catch (PGPException e)
        {
            // expected
        }
        
        try
        {
            testSigV3(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);

            fail("RSA V3 wrong key test failed.");
        }
        catch (PGPException e)
        {
            // expected
        }

        //
        // certifications
        //
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, "BC");
        
        sGen.initSign(PGPSignature.KEY_REVOCATION, pgpPrivKey);

        PGPSignature sig = sGen.generateCertification(secretKey.getPublicKey());
        
        sig.initVerify(secretKey.getPublicKey(), "BC");
        
        if (!sig.verifyCertification(secretKey.getPublicKey()))
        {
            fail("revocation verification failed.");
        }
        
        PGPSecretKeyRing pgpDSAPriv = new PGPSecretKeyRing(dsaKeyRing);         
        PGPSecretKey secretDSAKey = pgpDSAPriv.getSecretKey();        
        PGPPrivateKey pgpPrivDSAKey = secretDSAKey.extractPrivateKey(dsaPass, "BC");
        
        sGen = new PGPSignatureGenerator(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, "BC");
        
        sGen.initSign(PGPSignature.SUBKEY_BINDING, pgpPrivDSAKey);

        PGPSignatureSubpacketGenerator    unhashedGen = new PGPSignatureSubpacketGenerator();
        PGPSignatureSubpacketGenerator    hashedGen = new PGPSignatureSubpacketGenerator();
        
        hashedGen.setSignatureExpirationTime(false, 10000);
        hashedGen.setSignerUserID(true, TEST_USER_ID);

        sGen.setHashedSubpackets(hashedGen.generate());
        sGen.setUnhashedSubpackets(unhashedGen.generate());
        
        sig = sGen.generateCertification(secretDSAKey.getPublicKey(), secretKey.getPublicKey());
        
        sig.initVerify(secretDSAKey.getPublicKey(), "BC");
        
        if (!sig.verifyCertification(secretDSAKey.getPublicKey(), secretKey.getPublicKey()))
        {
            fail("subkey binding verification failed.");
        }
        
        PGPSignatureSubpacketVector hashedPcks = sig.getHashedSubPackets();
        PGPSignatureSubpacketVector unhashedPcks = sig.getHashedSubPackets();
        
        if (!hashedPcks.getSignerUserID().equals(TEST_USER_ID))
        {
            fail("test userid not matching");
        }
        
        if (hashedPcks.getSignatureExpirationTime() != TEST_EXPIRATION_TIME)
        {
            fail("test signature expiration time not matching");
        }
        
        sGen = new PGPSignatureGenerator(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, "BC");
        
        sGen.initSign(PGPSignature.SUBKEY_BINDING, pgpPrivDSAKey);

        sGen.setHashedSubpackets(null);
        sGen.setUnhashedSubpackets(null);

        sig = sGen.generateCertification(TEST_USER_ID, secretKey.getPublicKey());
        
        sig.initVerify(secretDSAKey.getPublicKey(), "BC");
        
        if (!sig.verifyCertification(TEST_USER_ID, secretKey.getPublicKey()))
        {
            fail("subkey binding verification failed.");
        }
        
        hashedPcks = sig.getHashedSubPackets();
        
        if (hashedPcks.size() != 2)
        {
            fail("found wrong number of hashed packets");
        }
        
        unhashedPcks = sig.getUnhashedSubPackets();
        
        if (unhashedPcks.size() != 0)
        {
            fail("found non-zero unhashed packets");
        }
        
        try
        {
            sig.verifyCertification(secretKey.getPublicKey());
            
            fail("failed to detect non-key signature.");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
        
        //
        // general signatures
        //
        testSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256, secretKey.getPublicKey(), pgpPrivKey);
        testSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA384, secretKey.getPublicKey(), pgpPrivKey);
        testSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA512, secretKey.getPublicKey(), pgpPrivKey);
        testSigV3(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);
        testTextSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
        testTextSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
        testTextSigV3(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
        testTextSigV3(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
        
        //
        // DSA Tests
        //
        pgpPriv = new PGPSecretKeyRing(dsaKeyRing);         
        secretKey = pgpPriv.getSecretKey();        
        pgpPrivKey = secretKey.extractPrivateKey(dsaPass, "BC");
        
        try
        {
            testSig(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);

            fail("DSA wrong key test failed.");
        }
        catch (PGPException e)
        {
            // expected
        }
        
        try
        {
            testSigV3(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);

            fail("DSA V3 wrong key test failed.");
        }
        catch (PGPException e)
        {
            // expected
        }
        
        testSig(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);
        testSigV3(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey);
        testTextSig(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
        testTextSig(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
        testTextSigV3(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA_WITH_CRLF, TEST_DATA_WITH_CRLF);
        testTextSigV3(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA1, secretKey.getPublicKey(), pgpPrivKey, TEST_DATA, TEST_DATA_WITH_CRLF);
    }

    private void testSig(
        int           encAlgorithm,
        int           hashAlgorithm,
        PGPPublicKey  pubKey,
        PGPPrivateKey privKey)
        throws Exception
    {            
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ByteArrayInputStream  testIn = new ByteArrayInputStream(TEST_DATA);
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(encAlgorithm, hashAlgorithm, "BC");
        
        sGen.initSign(PGPSignature.BINARY_DOCUMENT, privKey);
        sGen.generateOnePassVersion(false).encode(bOut);
    
        PGPLiteralDataGenerator    lGen = new PGPLiteralDataGenerator();
        OutputStream               lOut = lGen.open(bOut, PGPLiteralData.BINARY, "_CONSOLE", TEST_DATA.length * 2, new Date());
        
        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }
    
        lOut.write(TEST_DATA);
        sGen.update(TEST_DATA);
        
        lGen.close();
    
        sGen.generate().encode(bOut);
    
        verifySignature(bOut.toByteArray(), hashAlgorithm, pubKey, TEST_DATA);
    }
    
    private void testTextSig(
        int            encAlgorithm,
        int            hashAlgorithm,
        PGPPublicKey   pubKey,
        PGPPrivateKey  privKey,
        byte[]         data,
        byte[]         canonicalData)
        throws Exception
    {            
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(encAlgorithm, HashAlgorithmTags.SHA1, "BC");  
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ByteArrayInputStream  testIn = new ByteArrayInputStream(data);
        Date                  creationTime = new Date();
        
        sGen.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, privKey);
        sGen.generateOnePassVersion(false).encode(bOut);
    
        PGPLiteralDataGenerator    lGen = new PGPLiteralDataGenerator();
        OutputStream               lOut = lGen.open(bOut, PGPLiteralData.TEXT, "_CONSOLE", data.length * 2, creationTime);
        
        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }
    
        lOut.write(data);
        sGen.update(data);
        
        lGen.close();
    
        sGen.generate().encode(bOut);
    
        verifySignature(bOut.toByteArray(), hashAlgorithm, pubKey, canonicalData);
    }
    
    private void testSigV3(
        int           encAlgorithm,
        int           hashAlgorithm,
        PGPPublicKey  pubKey,
        PGPPrivateKey privKey)
        throws Exception
    {            
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ByteArrayInputStream    testIn = new ByteArrayInputStream(TEST_DATA);
        PGPV3SignatureGenerator sGen = new PGPV3SignatureGenerator(encAlgorithm, hashAlgorithm, "BC");
        
        sGen.initSign(PGPSignature.BINARY_DOCUMENT, privKey);
        sGen.generateOnePassVersion(false).encode(bOut);
    
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream            lOut = lGen.open(bOut, PGPLiteralData.BINARY, "_CONSOLE", TEST_DATA.length * 2, new Date());
        
        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }
    
        lOut.write(TEST_DATA);
        sGen.update(TEST_DATA);
        
        lGen.close();
    
        sGen.generate().encode(bOut);
    
        verifySignature(bOut.toByteArray(), hashAlgorithm, pubKey, TEST_DATA);
    }
    
    private void testTextSigV3(
        int            encAlgorithm,
        int            hashAlgorithm,
        PGPPublicKey   pubKey,
        PGPPrivateKey  privKey,
        byte[]         data,
        byte[]         canonicalData)
        throws Exception
    {            
        PGPV3SignatureGenerator sGen = new PGPV3SignatureGenerator(encAlgorithm, HashAlgorithmTags.SHA1, "BC");
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ByteArrayInputStream    testIn = new ByteArrayInputStream(data);
        
        sGen.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, privKey);
        sGen.generateOnePassVersion(false).encode(bOut);
    
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream            lOut = lGen.open(bOut, PGPLiteralData.TEXT, "_CONSOLE", data.length * 2, new Date());
        
        int ch;
        while ((ch = testIn.read()) >= 0)
        {
            lOut.write(ch);
            sGen.update((byte)ch);
        }
    
        lOut.write(data);
        sGen.update(data);
        
        lGen.close();
    
        sGen.generate().encode(bOut);
    
        verifySignature(bOut.toByteArray(), hashAlgorithm, pubKey, canonicalData);
    }
    
    private void verifySignature(
        byte[] encodedSig, 
        int hashAlgorithm, 
        PGPPublicKey pubKey,  
        byte[] original) 
        throws IOException, PGPException, NoSuchProviderException, SignatureException
    {
        PGPObjectFactory        pgpFact = new PGPObjectFactory(encodedSig);
        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature     ops = p1.get(0);
        PGPLiteralData          p2 = (PGPLiteralData)pgpFact.nextObject();
        InputStream             dIn = p2.getInputStream();
    
        ops.initVerify(pubKey, "BC");
        
        int ch;

        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
        }
    
        PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = p3.get(0);
        
        if (sig.getKeyID() != pubKey.getKeyID())
        {
            fail("key id mismatch in signature");
        }
        
        if (!ops.verify(sig))
        {
            fail("Failed generated signature check - " + hashAlgorithm);
        }
        
        sig.initVerify(pubKey, "BC");
        
        for (int i = 0; i != original.length; i++)
        {
            sig.update(original[i]);
        }
        
        sig.update(original);
        
        if (!sig.verify())
        {
            fail("Failed generated signature check against original data");
        }
    }
    
    public String getName()
    {
        return "PGPSignatureTest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPSignatureTest());
    }
}
