package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CMSTestUtil
{
    
    public static SecureRandom     rand;
    public static KeyPairGenerator kpg;
    public static KeyPairGenerator gostKpg;
    public static KeyGenerator     aes192kg;
    public static KeyGenerator     desede128kg;
    public static KeyGenerator     desede192kg;
    public static KeyGenerator     rc240kg;
    public static KeyGenerator     rc264kg;
    public static KeyGenerator     rc2128kg;
    public static BigInteger       serialNumber;
    
    public static final boolean DEBUG = true;
    
    static
    {
        try
        {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            rand = new SecureRandom();

            kpg  = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024, rand);
            
            gostKpg  = KeyPairGenerator.getInstance("GOST3410", "BC");
            GOST3410ParameterSpec gost3410P = new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_94_CryptoPro_A.getId());
            
            gostKpg.initialize(gost3410P, new SecureRandom());

            aes192kg = KeyGenerator.getInstance("AES", "BC");
            aes192kg.init(192, rand);

            desede128kg = KeyGenerator.getInstance("DESEDE", "BC");
            desede128kg.init(112, rand);

            desede192kg = KeyGenerator.getInstance("DESEDE", "BC");
            desede192kg.init(168, rand);

            rc240kg = KeyGenerator.getInstance("RC2", "BC");
            rc240kg.init(40, rand);
            
            rc264kg = KeyGenerator.getInstance("RC2", "BC");
            rc264kg.init(64, rand);
            
            rc2128kg = KeyGenerator.getInstance("RC2", "BC");
            rc2128kg.init(128, rand);
            
            serialNumber = new BigInteger("1");
        }
        catch(Exception ex)
        {
            ex.printStackTrace();
        }
    }
    
    public static String dumpBase64(
        byte[]  data)
    {
        StringBuffer    buf = new StringBuffer();
        
        data = Base64.encode(data);
        
        for (int i = 0; i < data.length; i += 64)
        {
            if (i + 64 < data.length)
            {
                buf.append(new String(data, i, 64));
            }
            else
            {
                buf.append(new String(data, i, data.length - i));
            }
            buf.append("\n");
        }
        
        return buf.toString();
    }
    
    public static KeyPair makeKeyPair()
    {
        return kpg.generateKeyPair();
    }

    public static KeyPair makeGostKeyPair()
    {
        return gostKpg.generateKeyPair();
    }

    public static SecretKey makeDesede128Key()
    {
        return desede128kg.generateKey();
    }

    public static SecretKey makeAES192Key()
    {
        return aes192kg.generateKey();
    }

    public static SecretKey makeDesede192Key()
    {
        return desede192kg.generateKey();
    }

    public static SecretKey makeRC240Key()
    {
        return rc240kg.generateKey();
    }

    public static SecretKey makeRC264Key()
    {
        return rc264kg.generateKey();
    }

    public static SecretKey makeRC2128Key()
    {
        return rc2128kg.generateKey();
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
            throws GeneralSecurityException, IOException
    {

        return makeCertificate(_subKP, _subDN, _issKP, _issDN, false);
    }

    public static X509Certificate makeCACertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
            throws GeneralSecurityException, IOException
    {

        return makeCertificate(_subKP, _subDN, _issKP, _issDN, true);
    }
    
    
    public static X509Certificate makeCertificate(KeyPair _subKP, String _subDN, KeyPair _issKP, String _issDN, boolean _ca) 
        throws GeneralSecurityException, IOException
    {

        PublicKey  _subPub  = _subKP.getPublic();
        PrivateKey _issPriv = _issKP.getPrivate();
        PublicKey  _issPub  = _issKP.getPublic();
        
        X509V3CertificateGenerator _v3CertGen = new X509V3CertificateGenerator();
        
        _v3CertGen.reset();
        _v3CertGen.setSerialNumber(allocateSerialNumber());
        _v3CertGen.setIssuerDN(new X509Name(_issDN));
        _v3CertGen.setNotBefore(new Date(System.currentTimeMillis()));
        _v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)));
        _v3CertGen.setSubjectDN(new X509Name(_subDN));
        _v3CertGen.setPublicKey(_subPub);
        
        if (_subPub instanceof RSAPublicKey)
        {
            _v3CertGen.setSignatureAlgorithm("MD5WithRSAEncryption");
        }
        else
        {
            _v3CertGen.setSignatureAlgorithm("GOST3411WithGOST3410");
        }

        _v3CertGen.addExtension(
            X509Extensions.SubjectKeyIdentifier,
            false,
            createSubjectKeyId(_subPub));

        _v3CertGen.addExtension(
            X509Extensions.AuthorityKeyIdentifier,
            false,
            createAuthorityKeyId(_issPub));

        _v3CertGen.addExtension(
            X509Extensions.BasicConstraints,
            false,
            new BasicConstraints(_ca));

        X509Certificate _cert = _v3CertGen.generateX509Certificate(_issPriv);

        _cert.checkValidity(new Date());
        _cert.verify(_issPub);

        return _cert;
    }
    


    /*  
     *  
     *  INTERNAL METHODS
     *  
     */ 
    
    private static AuthorityKeyIdentifier createAuthorityKeyId(
        PublicKey _pubKey)
        throws IOException
    {

        ByteArrayInputStream _bais = new ByteArrayInputStream(_pubKey
                .getEncoded());
        SubjectPublicKeyInfo _info = new SubjectPublicKeyInfo(
                (ASN1Sequence)new ASN1InputStream(_bais).readObject());

        return new AuthorityKeyIdentifier(_info);
    }

    private static SubjectKeyIdentifier createSubjectKeyId(
        PublicKey _pubKey)
        throws IOException
    {

        ByteArrayInputStream _bais = new ByteArrayInputStream(_pubKey
                .getEncoded());
        SubjectPublicKeyInfo _info = new SubjectPublicKeyInfo(
                (ASN1Sequence)new ASN1InputStream(_bais).readObject());
        return new SubjectKeyIdentifier(_info);
    }

    private static BigInteger allocateSerialNumber()
    {
        BigInteger _tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return _tmp;
    }
    
    public static byte[] streamToByteArray(
        InputStream in) 
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int ch;
        
        while ((ch = in.read()) >= 0)
        {
            bOut.write(ch);
        }
        
        return bOut.toByteArray();
    }
}
