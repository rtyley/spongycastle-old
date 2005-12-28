package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class SMIMETestUtil
{    
    public static SecureRandom     rand;
    public static KeyPairGenerator kpg;
    public static KeyPairGenerator dsaKpg;
    public static KeyGenerator     desede128kg;
    public static KeyGenerator     desede192kg;
    public static KeyGenerator     rc240kg;
    public static BigInteger       serialNumber;
    
    public static final boolean DEBUG = true;

    static
    {
        Security.addProvider(new BouncyCastleProvider());
        
        try
        {
            rand = new SecureRandom();

            kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024, rand);

            dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
            dsaKpg.initialize(1024, rand);

            desede128kg = KeyGenerator.getInstance("DESEDE", "BC");
            desede128kg = KeyGenerator.getInstance("DESEDE", "BC");
            desede128kg.init(112, rand);

            desede192kg = KeyGenerator.getInstance("DESEDE", "BC");
            desede192kg.init(168, rand);

            rc240kg = KeyGenerator.getInstance("RC2", "BC");
            rc240kg.init(40, rand);

            serialNumber = new BigInteger("1");
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.toString());
        }
    }

    /*  
     *  
     *  CRYPT
     *  
     */

    public static KeyPair makeKeyPair()
    {
        return kpg.generateKeyPair();
    }

    public static KeyPair makeDSAKeyPair()
    {
        return dsaKpg.generateKeyPair();
    }

    public static SecretKey makeDesede128Key()
    {
        return desede128kg.generateKey();
    }

    public static SecretKey makeDesede192Key()
    {
        return desede192kg.generateKey();
    }

    public static SecretKey makeRC240Key()
    {
        return rc240kg.generateKey();
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
            throws GeneralSecurityException, IOException
    {
        PublicKey _subPub = _subKP.getPublic();
        PrivateKey _issPriv = _issKP.getPrivate();
        PublicKey _issPub = _issKP.getPublic();

        X509V3CertificateGenerator _v3CertGen = new X509V3CertificateGenerator();

        _v3CertGen.reset();
        _v3CertGen.setSerialNumber(allocateSerialNumber());
        _v3CertGen.setIssuerDN(new X509Name(_issDN));
        _v3CertGen.setNotBefore(new Date(System.currentTimeMillis()));
        _v3CertGen.setNotAfter(new Date(System.currentTimeMillis()
                + (1000L * 60 * 60 * 24 * 100)));
        _v3CertGen.setSubjectDN(new X509Name(_subDN));
        _v3CertGen.setPublicKey(_subPub);

        if (_issKP.getPrivate() instanceof RSAPrivateKey)
        {
            _v3CertGen.setSignatureAlgorithm("MD5WithRSAEncryption");
        }
        else
        {
            _v3CertGen.setSignatureAlgorithm("SHA1WithDSA");
        }

        _v3CertGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                createSubjectKeyId(_subPub));

        _v3CertGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                createAuthorityKeyId(_issPub));

        _v3CertGen.addExtension(X509Extensions.BasicConstraints, false,
                new BasicConstraints(false));

        X509Certificate _cert = _v3CertGen.generateX509Certificate(_issPriv);

        _cert.checkValidity(new Date());
        _cert.verify(_issPub);

        return _cert;
    }

    /*  
     *  
     *  MAIL
     *  
     */

    public static MimeBodyPart makeMimeBodyPart(String _msg)
            throws MessagingException
    {

        MimeBodyPart _mbp = new MimeBodyPart();
        _mbp.setText(_msg);
        return _mbp;
    }

    public static MimeBodyPart makeMimeBodyPart(MimeMultipart _mm)
            throws MessagingException
    {

        MimeBodyPart _mbp = new MimeBodyPart();
        _mbp.setContent(_mm, _mm.getContentType());
        return _mbp;
    }

    public static MimeMultipart makeMimeMultipart(String _msg1, String _msg2)
            throws MessagingException
    {

        MimeMultipart _mm = new MimeMultipart();
        _mm.addBodyPart(makeMimeBodyPart(_msg1));
        _mm.addBodyPart(makeMimeBodyPart(_msg2));

        return _mm;
    }

    /*  
     *  
     *  INTERNAL METHODS
     *  
     */

    private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey _pubKey)
            throws IOException
    {

        ByteArrayInputStream _bais = new ByteArrayInputStream(_pubKey
                .getEncoded());
        SubjectPublicKeyInfo _info = new SubjectPublicKeyInfo(
                (ASN1Sequence)new ASN1InputStream(_bais).readObject());

        return new AuthorityKeyIdentifier(_info);
    }

    private static SubjectKeyIdentifier createSubjectKeyId(PublicKey _pubKey)
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
        serialNumber = serialNumber.add(new BigInteger("1"));
        return _tmp;
    }
}
