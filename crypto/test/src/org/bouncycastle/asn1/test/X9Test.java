package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class X9Test
    extends SimpleTest
{
    private byte[] namedPub = Base64.decode("MBowEwYHKoZIzj0CAQYIKoZIzj0DAQEDAwADAQ==");
    private byte[] expPub = Base64.decode(
                "MIHcMIHUBgcqhkjOPQIBMIHIAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAA"
              + "AAAH///////zBXBB5///////////////9///////+AAAAAAAB///////wEHiVXBfoqMGZUsfTL"
              + "A9anUKMMJQEC1JiHF9m6FattPgMVAH1zdBaP/jRxtgqFdoahlHXTv6L/BB8DZ2iujhi7ks/PAF"
              + "yUmqLG2UhT0OZgu/hUsclQX+laAh5///////////////9///+XXetBs6YFfDxDIUZSZVEDAwAD"
              + "AQ==");

    private byte[] namedPriv = Base64.decode("MCICAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEECDAGAgEBBAEK");
    private byte[] expPriv = Base64.decode(
                "MIHkAgEAMIHUBgcqhkjOPQIBMIHIAgEBMCkGByqGSM49AQECHn///////////////3///////4"
              + "AAAAAAAH///////zBXBB5///////////////9///////+AAAAAAAB///////wEHiVXBfoqMGZU"
              + "sfTLA9anUKMMJQEC1JiHF9m6FattPgMVAH1zdBaP/jRxtgqFdoahlHXTv6L/BB8DZ2iujhi7ks"
              + "/PAFyUmqLG2UhT0OZgu/hUsclQX+laAh5///////////////9///+XXetBs6YFfDxDIUZSZVEE"
              + "CDAGAgEBBAEU");
 
    private void encodePublicKey()
        throws Exception
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        X9ECParameters          ecP = X962NamedCurves.getByOID(X9ObjectIdentifiers.prime239v3);

        //
        // named curve
        //
        X962Parameters          params = new X962Parameters(X9ObjectIdentifiers.prime192v1);

        ASN1OctetString         p = (ASN1OctetString)(new X9ECPoint(new ECPoint.Fp(ecP.getCurve(), new ECFieldElement.Fp(BigInteger.valueOf(2), BigInteger.valueOf(1)), new ECFieldElement.Fp(BigInteger.valueOf(4), BigInteger.valueOf(3)), true)).getDERObject());

        SubjectPublicKeyInfo    info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), p.getOctets());

        if (!areEqual(info.getEncoded(), namedPub))
        {
            fail("failed public named generation");
        }
        
        ASN1InputStream         aIn = new ASN1InputStream(new ByteArrayInputStream(namedPub));
        DERObject               o = aIn.readObject();
        
        if (!info.equals(o))
        {
            fail("failed public named equality");
        }
        
        //
        // explicit curve parameters
        //
        params = new X962Parameters(ecP);
        
        info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), p.getOctets());

        if (!areEqual(info.getEncoded(), expPub))
        {
            fail("failed public explicit generation");
        }
        
        aIn = new ASN1InputStream(new ByteArrayInputStream(expPub));
        o = aIn.readObject();
        
        if (!info.equals(o))
        {
            fail("failed public explicit equality");
        }
    }
    
    private void encodePrivateKey()
        throws Exception
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        X9ECParameters          ecP = X962NamedCurves.getByOID(X9ObjectIdentifiers.prime239v3);

        //
        // named curve
        //
        X962Parameters          params = new X962Parameters(X9ObjectIdentifiers.prime192v1);

        ASN1OctetString         p = (ASN1OctetString)(new X9ECPoint(new ECPoint.Fp(ecP.getCurve(), new ECFieldElement.Fp(BigInteger.valueOf(2), BigInteger.valueOf(1)), new ECFieldElement.Fp(BigInteger.valueOf(4), BigInteger.valueOf(3)), true)).getDERObject());

        PrivateKeyInfo          info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), new ECPrivateKeyStructure(BigInteger.valueOf(10)).getDERObject());

        if (!areEqual(info.getEncoded(), namedPriv))
        {
            fail("failed private named generation");
        }
        
        ASN1InputStream         aIn = new ASN1InputStream(new ByteArrayInputStream(namedPriv));
        DERObject               o = aIn.readObject();
        
        if (!info.equals(o))
        {
            fail("failed private named equality");
        }
        
        //
        // explicit curve parameters
        //
        params = new X962Parameters(ecP);
        
        info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), new ECPrivateKeyStructure(BigInteger.valueOf(20)).toASN1Object());

        if (!areEqual(info.getEncoded(), expPriv))
        {
            fail("failed private explicit generation");
        }
        
        aIn = new ASN1InputStream(new ByteArrayInputStream(expPriv));
        o = aIn.readObject();
        
        if (!info.equals(o))
        {
            fail("failed private explicit equality");
        }
    }
    
    public void performTest()
        throws Exception
    {
        encodePublicKey();
        encodePrivateKey();
    }

    public String getName()
    {
        return "X9";
    }

    public static void main(
        String[]    args)
    {
        runTest(new X9Test());
    }
}
