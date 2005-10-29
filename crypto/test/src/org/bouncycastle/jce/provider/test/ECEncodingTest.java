package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class ECEncodingTest
    implements Test
{
    public String getName()
    {
        return "ECEncodingTest";
    }
    
    public TestResult perform()
    {
        try
        {
            byte[] ecParams = Hex.decode("3081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43041C2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B0439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD021D00D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F020101");
            TestResult res = testParams(ecParams, true);
            
            if (!res.isSuccessful())
            {
                return res;
                
            }
            
            res = testParams(ecParams, false);
            
            if (!res.isSuccessful())
            {
                return res;
                
            }
            
            ecParams = Hex.decode("3081C8020101302806072A8648CE3D0101021D00D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF303C041C56E6C7E4F11A7B4B961A4DCB5BD282EB22E42E9BCBE3E7B361F18012041C4BE3E7B361F18012F2353D22975E02D8D05D2C6F3342DD8F57D4C76F0439048D127A0C27E0DE207ED3B7FB98F83C8BD5A2A57C827F4B97874DEB2C1BAEB0C006958CE61BB1FC81F5389E288CB3E86E2ED91FB47B08FCCA021D00D7C134AA264366862A18302575D11A5F7AABFBA3D897FF5CA727AF53020101");
            res = testParams(ecParams, true);
            
            if (!res.isSuccessful())
            {
                return res;
                
            }
            
            res = testParams(ecParams, false);
            
            if (!res.isSuccessful())
            {
                return res;
                
            }
            
            ecParams = Hex.decode("30820142020101303c06072a8648ce3d0101023100fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff3066043100fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc043100b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef046104aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f023100ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973020101");
            res = testParams(ecParams, true);
            
            if (!res.isSuccessful())
            {
                return res;
                
            }
            
            res = testParams(ecParams, false);
            
            if (!res.isSuccessful())
            {
                return res;
                
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Exception " + e, e);
        }
    }
    
    private TestResult testParams(byte[] ecParameterEncoded, boolean compress)
            throws Exception
    {
        String keyStorePass = "myPass";
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(
                ecParameterEncoded));
        X9ECParameters params = new X9ECParameters((ASN1Sequence)in
                .readObject());
        KeyPair kp = null;
        boolean success = false;
        while (!success)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA");
            kpg.initialize(new ECParameterSpec(params.getCurve(),
                    params.getG(), params.getN(), params.getH(), params
                            .getSeed()));
            kp = kpg.generateKeyPair();
            // The very old Problem... we need a certificate chain to
            // save a private key...
            JCEECPublicKey pubKey = (JCEECPublicKey)kp.getPublic();
            if (!compress)
            {
                pubKey.setPointFormat("UNCOMPRESSED");
            }
            byte[] x = pubKey.getQ().getX().toBigInteger().toByteArray();
            byte[] y = pubKey.getQ().getY().toBigInteger().toByteArray();
            if (x.length == y.length)
            {
                success = true;
            }
        }

        // The very old Problem... we need a certificate chain to
        // save a private key...

        Certificate[] chain = new Certificate[] { generateSelfSignedSoftECCert(
                kp, compress) };

        KeyStore keyStore = KeyStore.getInstance("BKS");
        keyStore.load(null, keyStorePass.toCharArray());

        keyStore.setCertificateEntry("ECCert", chain[0]);

        JCEECPrivateKey privateECKey = (JCEECPrivateKey)kp.getPrivate();
        keyStore.setKeyEntry("ECPrivKey", privateECKey, keyStorePass
                .toCharArray(), chain);

        // Test ec sign / verify
        JCEECPublicKey pub = (JCEECPublicKey)kp.getPublic();
        String oldPrivateKey = new String(Hex.encode(privateECKey.getEncoded()));
        String oldPublicKey = new String(Hex.encode(pub.getEncoded()));
        JCEECPrivateKey newKey = (JCEECPrivateKey)keyStore.getKey("ECPrivKey",
                keyStorePass.toCharArray());
        JCEECPublicKey newPubKey = (JCEECPublicKey)keyStore.getCertificate(
                "ECCert").getPublicKey();
        if (!compress)
        {
            newKey.setPointFormat("UNCOMPRESSED");
            newPubKey.setPointFormat("UNCOMPRESSED");
        }

        String newPrivateKey = new String(Hex.encode(newKey.getEncoded()));
        String newPublicKey = new String(Hex.encode(newPubKey.getEncoded()));

        if (!oldPrivateKey.equals(newPrivateKey))
        {
            return new SimpleTestResult(false, getName()
                    + ": failed private key comparison");
        }

        if (!oldPublicKey.equals(newPublicKey))
        {
            return new SimpleTestResult(false, getName()
                    + ": failed private key comparison");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    /**
     * Create a self signed cert for our software emulation
     * 
     * @param kp
     *            is the keypair for our certificate
     * @return a self signed cert for our software emulation
     * @throws InvalidKeyException
     *             on error
     * @throws SignatureException
     *             on error
     */
    private X509Certificate generateSelfSignedSoftECCert(KeyPair kp,
            boolean compress) throws InvalidKeyException, SignatureException
    {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        JCEECPrivateKey privECKey = (JCEECPrivateKey)kp.getPrivate();
        JCEECPublicKey pubECKey = (JCEECPublicKey)kp.getPublic();
        if (!compress)
        {
            privECKey.setPointFormat("UNCOMPRESSED");
            pubECKey.setPointFormat("UNCOMPRESSED");
        }
        certGen.setSignatureAlgorithm("ECDSAwithSHA1");
        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X509Principal("CN=Software emul (EC Cert)"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000000));
        certGen.setSubjectDN(new X509Principal("CN=Software emul (EC Cert)"));
        certGen.setPublicKey((PublicKey)pubECKey);

        return certGen.generateX509Certificate((PrivateKey)privECKey);
    }
    

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new ECEncodingTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }

}
