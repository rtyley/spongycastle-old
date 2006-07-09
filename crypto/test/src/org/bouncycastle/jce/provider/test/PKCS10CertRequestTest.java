package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Hashtable;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 **/
public class PKCS10CertRequestTest
    extends SimpleTest
{
    private byte[] gost3410EC_A = Base64.decode(
  "MIIBOzCB6wIBADB/MQ0wCwYDVQQDEwR0ZXN0MRUwEwYDVQQKEwxEZW1vcyBDbyBMdGQxHjAcBgNV"
 +"BAsTFUNyeXB0b2dyYXBoeSBkaXZpc2lvbjEPMA0GA1UEBxMGTW9zY293MQswCQYDVQQGEwJydTEZ"
 +"MBcGCSqGSIb3DQEJARYKc2RiQGRvbC5ydTBjMBwGBiqFAwICEzASBgcqhQMCAiMBBgcqhQMCAh4B"
 +"A0MABEBYx0P2D7YuuZo5HgdIAUKAXcLBDZ+4LYFgbKjrfStVfH59lc40BQ2FZ7M703hLpXK8GiBQ"
 +"GEYpKaAuQZnMIpByoAAwCAYGKoUDAgIDA0EAgXMcTrhdOY2Er2tHOSAgnMezqrYxocZTWhxmW5Rl"
 +"JY6lbXH5rndCn4swFzXU+YhgAsJv1wQBaoZEWRl5WV4/nA==");

    private byte[] gost3410EC_B = Base64.decode(
  "MIIBPTCB7QIBADCBgDENMAsGA1UEAxMEdGVzdDEWMBQGA1UEChMNRGVtb3MgQ28gTHRkLjEeMBwG"
 +"A1UECxMVQ3J5cHRvZ3JhcGh5IGRpdmlzaW9uMQ8wDQYDVQQHEwZNb3Njb3cxCzAJBgNVBAYTAnJ1"
 +"MRkwFwYJKoZIhvcNAQkBFgpzZGJAZG9sLnJ1MGMwHAYGKoUDAgITMBIGByqFAwICIwIGByqFAwIC"
 +"HgEDQwAEQI5SLoWT7dZVilbV9j5B/fyIDuDs6x4pjqNC2TtFYbpRHrk/Wc5g/mcHvD80tsm5o1C7"
 +"7cizNzkvAVUM4VT4Dz6gADAIBgYqhQMCAgMDQQAoT5TwJ8o+bSrxckymyo3diwG7ZbSytX4sRiKy"
 +"wXPWRS9LlBvPO2NqwpS2HUnxSU8rzfL9fJcybATf7Yt1OEVq");

    private byte[] gost3410EC_C = Base64.decode(
  "MIIBRDCB9AIBADCBhzEVMBMGA1UEAxMMdGVzdCByZXF1ZXN0MRUwEwYDVQQKEwxEZW1vcyBDbyBM"
 +"dGQxHjAcBgNVBAsTFUNyeXB0b2dyYXBoeSBkaXZpc2lvbjEPMA0GA1UEBxMGTW9zY293MQswCQYD"
 +"VQQGEwJydTEZMBcGCSqGSIb3DQEJARYKc2RiQGRvbC5ydTBjMBwGBiqFAwICEzASBgcqhQMCAiMD"
 +"BgcqhQMCAh4BA0MABEBcmGh7OmR4iqqj+ycYo1S1fS7r5PhisSQU2Ezuz8wmmmR2zeTZkdMYCOBa"
 +"UTMNms0msW3wuYDho7nTDNscHTB5oAAwCAYGKoUDAgIDA0EAVoOMbfyo1Un4Ss7WQrUjHJoiaYW8"
 +"Ime5LeGGU2iW3ieAv6es/FdMrwTKkqn5dhd3aL/itFg5oQbhyfXw5yw/QQ==");
    
    private byte[] gost3410EC_ExA = Base64.decode(
     "MIIBOzCB6wIBADB/MQ0wCwYDVQQDEwR0ZXN0MRUwEwYDVQQKEwxEZW1vcyBDbyBMdGQxHjAcBgNV"
   + "BAsTFUNyeXB0b2dyYXBoeSBkaXZpc2lvbjEPMA0GA1UEBxMGTW9zY293MQswCQYDVQQGEwJydTEZ"
   + "MBcGCSqGSIb3DQEJARYKc2RiQGRvbC5ydTBjMBwGBiqFAwICEzASBgcqhQMCAiQABgcqhQMCAh4B"
   + "A0MABEDkqNT/3f8NHj6EUiWnK4JbVZBh31bEpkwq9z3jf0u8ZndG56Vt+K1ZB6EpFxLT7hSIos0w"
   + "weZ2YuTZ4w43OgodoAAwCAYGKoUDAgIDA0EASk/IUXWxoi6NtcUGVF23VRV1L3undB4sRZLp4Vho"
   + "gQ7m3CMbZFfJ2cPu6QyarseXGYHmazoirH5lGjEo535c1g==");

    private byte[] gost3410EC_ExB = Base64.decode(
      "MIIBPTCB7QIBADCBgDENMAsGA1UEAxMEdGVzdDEWMBQGA1UEChMNRGVtb3MgQ28gTHRkLjEeMBwG"
    + "A1UECxMVQ3J5cHRvZ3JhcGh5IGRpdmlzaW9uMQ8wDQYDVQQHEwZNb3Njb3cxCzAJBgNVBAYTAnJ1"
    + "MRkwFwYJKoZIhvcNAQkBFgpzZGJAZG9sLnJ1MGMwHAYGKoUDAgITMBIGByqFAwICJAEGByqFAwIC"
    + "HgEDQwAEQMBWYUKPy/1Kxad9ChAmgoSWSYOQxRnXo7KEGLU5RNSXA4qMUvArWzvhav+EYUfTbWLh"
    + "09nELDyHt2XQcvgQHnSgADAIBgYqhQMCAgMDQQAdaNhgH/ElHp64mbMaEo1tPCg9Q22McxpH8rCz"
    + "E0QBpF4H5mSSQVGI5OAXHToetnNuh7gHHSynyCupYDEHTbkZ");

    public String getName()
    {
        return "PKCS10CertRequest";
    }

    private void generationTest(int keySize, String keyName, String sigName, String provider)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyName, "BC");

        kpg.initialize(keySize);

        KeyPair kp = kpg.genKeyPair();

        Hashtable                   attrs = new Hashtable();

        attrs.put(X509Principal.C, "AU");
        attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Principal.L, "Melbourne");
        attrs.put(X509Principal.ST, "Victoria");
        attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");

        X509Name    subject = new X509Name(attrs);

        PKCS10CertificationRequest req1 = new PKCS10CertificationRequest(
                                                    sigName,
                                                    subject,
                                                    kp.getPublic(),
                                                    null,
                                                    kp.getPrivate(), provider);
                            
        byte[]  bytes = req1.getEncoded();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bytes);

        if (!req2.verify(provider))
        {
            fail(sigName + ": Failed verify check.");
        }

        if (!req2.getPublicKey(provider).equals(req1.getPublicKey(provider)))
        {
            fail(keyName + ": Failed public key check.");
        }
    }
    
    public void performTest()
        throws Exception
    {
        generationTest(512, "RSA", "SHA1withRSA", "BC");       
        generationTest(512, "GOST3410", "GOST3411withGOST3410", "BC");
        
        if (Security.getProvider("SunRsaSign") != null)
        {
            generationTest(512, "RSA", "SHA1withRSA", "SunRsaSign"); 
        }
        
        // elliptic curve GOST A parameter set
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(gost3410EC_A);
        if (!req.verify())
        {
            fail("Failed verify check gost3410EC_A.");
        }

        // elliptic curve GOST B parameter set
        req = new PKCS10CertificationRequest(gost3410EC_B);
        if (!req.verify())
        {
            fail("Failed verify check gost3410EC_B.");
        }

        // elliptic curve GOST C parameter set
        req = new PKCS10CertificationRequest(gost3410EC_C);
        if (!req.verify())
        {
            fail("Failed verify check gost3410EC_C.");
        }
        
        // elliptic curve GOST ExA parameter set
        req = new PKCS10CertificationRequest(gost3410EC_ExA);
        if (!req.verify())
        {
            fail("Failed verify check gost3410EC_ExA.");
        }

        // elliptic curve GOST ExB parameter set
        req = new PKCS10CertificationRequest(gost3410EC_ExB);
        if (!req.verify())
        {
            fail("Failed verify check gost3410EC_ExA.");
        }
        
        // elliptic curve openSSL
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

        ECCurve curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec ecSpec = new ECParameterSpec(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n

        g.initialize(ecSpec, new SecureRandom());

        KeyPair kp = g.generateKeyPair();

        req = new PKCS10CertificationRequest(
                "ECDSAWITHSHA1", new X509Name("CN=XXX"), kp.getPublic(), null, kp.getPrivate());
        if (!req.verify())
        {
            fail("Failed verify check EC.");
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PKCS10CertRequestTest());
    }
}
