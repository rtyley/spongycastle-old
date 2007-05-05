package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

public class CertPathTest
    extends SimpleTest
{
    static byte[] rootCertBin = Hex.decode(
        "3082023c308201a5a003020102020101300d06092a864886f70d0101040500305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d617279204365727469666963617465301e170d3032303132323133353230385a170d3032303332333133353230385a305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d61727920436572746966696361746530819d300d06092a864886f70d010101050003818b0030818702818100b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5020111a310300e300c0603551d13040530030101ff300d06092a864886f70d0101040500038181002584a067f9d3e9a02efcf33d9fb870176311ad7741551397a3717cfa71f8724907bdfe9846d25205c9241631df9c0dabd5a980ccdb69fdfcad3694fbe6939f7dffd730d67242400b6fcc9aa718e87f1d7ea58832e4f47d253c7843cc6f4c0a206fb141b959ff639b986cc3470bd576f176cf4d4f402b549ec14e90349b8fb8f5");
    static byte[] interCertBin = Hex.decode(
        "308202fe30820267a003020102020102300d06092a864886f70d0101040500305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d617279204365727469666963617465301e170d3032303132323133353230395a170d3032303332333133353230395a3061310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531283026060355040b131f426f756e637920496e7465726d65646961746520436572746966696361746530819f300d06092a864886f70d010101050003818d00308189028181008de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69020300ffffa381ca3081c7301d0603551d0e041604149408336f3240f78737dad120aaed2ea76ec9c91e3081840603551d23047d307b8014c0361907adc48897a85e726f6b09ebe5e6f1295ca160a45e305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d617279204365727469666963617465820101300c0603551d13040530030101ff301106096086480186f8420101040403020060300d06092a864886f70d010104050003818100a06b166b48c82ba1f81c8f142c14974050266f7b9d003e39e24e53d6f82ce43f4099937aa69b818a5193c5a842521cdb59a44b8837c2caddea70d8e013d6c9fd5e572010ee5cc6894c91783af13909eb53bd79d3c9bf6e268b0c13c41c6b16365287975683ece8a4dad9c8394faf707a00348ed01ac59287734411af4e878486");
    static byte[] finalCertBin = Hex.decode(
        "30820259308201c2a003020102020103300d06092a864886f70d01010405003061310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531283026060355040b131f426f756e637920496e7465726d656469617465204365727469666963617465301e170d3032303132323133353230395a170d3032303332333133353230395a3065310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531123010060355040713094d656c626f75726e65311830160603550403130f4572696320482e2045636869646e61305a300d06092a864886f70d01010105000349003046024100b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7020111a3633061301d0603551d0e04160414d06cec6d3583bc55121b0ccb3efed726a6166468301f0603551d230418301680149408336f3240f78737dad120aaed2ea76ec9c91e300c0603551d1304053003010100301106096086480186f8420101040403020001300d06092a864886f70d010104050003818100135db1857d0bb8bf108ce4df2cba4d1cf9e4a4578c0197b4da4e6ddd4c62d25debc5ed0916341aa577caa8eebf21409f065bb94369e3f006536a0a715c429c5888504b84030a181c88cb72fc99c11571d3171f869865cee722af474b5279df9ccd6ec3b04bf0fae272ca15266b74a5ce2d14548a0c76a07b4f97dbc25ed7d0ef");
    static byte[] rootCrlBin = Hex.decode(
        "3082012430818e020101300d06092a864886f70d0101050500305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d617279204365727469666963617465170d3032303132323133353230395a170d3032303332333133353230395a300d06092a864886f70d0101050500038181001255a218c620add68a7a8a561f331d2d510b42515c53f3701f2f49946ff2513a0c6e8e606e3488679f8354dc06a79a84c5233c9c9c9f746bbf4d19e49e730850b3bb7e672d59200d3da12512a91f7bc6f56036250789860ade5b0859a2a8fd24904b271624a544c8e894f293bb0f7018679e3499bf06548618ba473b7852a577");
    static byte[] interCrlBin = Hex.decode(
        "30820129308193020101300d06092a864886f70d01010505003061310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531283026060355040b131f426f756e637920496e7465726d656469617465204365727469666963617465170d3032303132323133353230395a170d3032303332333133353230395a300d06092a864886f70d01010505000381810046e2743d2faa0a3ed3555fc860a6fed78da96ce967c0db6ec8f40de95ec8cab9c720698d705f1cd8a75a400c0b15f23751cdfd5491abb9d416f0585f425e6802a3612a30cecd593abdcd15c632e0a4e2a7a3049649138ae0367431dd626d079c13c1449058547d796f53660acd5b432e7dacf31315ed3c21eb8948a7c043f418");

    /*
     * certpath with a circular reference
     */
    static byte[] certA = Base64.decode(
        "MIIC6jCCAlOgAwIBAgIBBTANBgkqhkiG9w0BAQUFADCBjTEPMA0GA1UEAxMGSW50"
      + "ZXIzMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX"
      + "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq"
      + "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ2NTda"
      + "Fw0xNzAzMzAwODQ0MDBaMIGlMScwJQYDVQQDHh4AQQByAG0AaQBuACAASADkAGIA"
      + "ZQByAGwAaQBuAGcxCzAJBgNVBAYTAkNIMQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNV"
      + "BAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNwaGVyZSBBRzEQMA4GA1UECxMHVGVzdGlu"
      + "ZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5AcHJpdmFzcGhlcmUuY29tMIGfMA0GCSqG"
      + "SIb3DQEBAQUAA4GNADCBiQKBgQCfHfyVs5dbxG35H/Thd29qR4NZU88taCu/OWA1"
      + "GdACI02lXWYpmLWiDgnU0ULP+GG8OnVp1IES9fz2zcrXKQ19xZzsen/To3h5sNte"
      + "cJpS00XMM24q/jDwy5NvkBP9YIfFKQ1E/0hFHXcqwlw+b/y/v6YGsZCU2h6QDzc4"
      + "5m0+BwIDAQABo0AwPjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIE8DAeBglg"
      + "hkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBBQUAA4GBAJEu"
      + "KiSfIwsY7SfobMLrv2v/BtLhGLi4RnmjiwzBhuv5rn4rRfBpq1ppmqQMJ2pmA67v"
      + "UWCY+mNwuyjHyivpCCyJGsZ9d5H09g2vqxzkDBMz7X9VNMZYFH8j/R3/Cfvqks31"
      + "z0OFslJkeKLa1I0P/dfVHsRKNkLRT3Ws5LKksErQ");

    static byte[] certB = Base64.decode(
        "MIICtTCCAh6gAwIBAgIBBDANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50"
      + "ZXIyMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX"
      + "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq"
      + "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ2Mzha"
      + "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjMxCzAJBgNVBAYTAkNI"
      + "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw"
      + "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A"
      + "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxCXIB"
      + "QRnmVvl2h7Q+0SsRxDLnyM1dJG9jMa+UCCmHy0k/ZHs5VirSbjEJSjkQ9BGeh9SC"
      + "7JwbMpXO7UE+gcVc2RnWUY+MA+fWIeTV4KtkYA8WPu8wVGCXbN8wwh/StOocszxb"
      + "g+iLvGeh8CYSRqg6QN3S/02etH3o8H4e7Z0PZwIDAQABoyMwITAPBgNVHRMBAf8E"
      + "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCtWdirSsmt"
      + "+CBBCNn6ZnbU3QqQfiiQIomjenNEHESJgaS/+PvPE5i3xWFXsunTHLW321/Km16I"
      + "7+ZvT8Su1cqHg79NAT8QB0yke1saKSy2C0Pic4HwrNqVBWFNSxMU0hQzpx/ZXDbZ"
      + "DqIXAp5EfyRYBy2ul+jm6Rot6aFgzuopKg==");

    static byte[] certC = Base64.decode(
        "MIICtTCCAh6gAwIBAgIBAjANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50"
      + "ZXIxMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX"
      + "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq"
      + "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ0Mzla"
      + "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjIxCzAJBgNVBAYTAkNI"
      + "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw"
      + "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A"
      + "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD0rLr6"
      + "f2/ONeJzTb0q9M/NNX+MnAFMSqiQGVBkT76u5nOH4KLkpHXkzI82JI7GuQMzoT3a"
      + "+RP1hO6FneO92ms2soC6xiOFb4EC69Dfhh87Nww5O35JxVF0bzmbmIAWd6P/7zGh"
      + "nd2S4tKkaZcubps+C0j9Fgi0hipVicAOUVVoDQIDAQABoyMwITAPBgNVHRMBAf8E"
      + "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCLPvc1IMA4"
      + "YP+PmnEldyUoRWRnvPWjBGeu0WheBP7fdcnGBf93Nmc5j68ZN+eTZ5VMuZ99YdvH"
      + "CXGNX6oodONLU//LlFKdLl5xjLAS5X9p1RbOEGytnalqeiEpjk4+C/7rIBG1kllO"
      + "dItmI6LlEMV09Hkpg6ZRAUmRkb8KrM4X7A==");

    static byte[] certD = Base64.decode(
        "MIICtTCCAh6gAwIBAgIBBjANBgkqhkiG9w0BAQQFADCBjTEPMA0GA1UEAxMGSW50"
      + "ZXIzMQswCQYDVQQGEwJDSDEPMA0GA1UEBxMGWnVyaWNoMQswCQYDVQQIEwJaSDEX"
      + "MBUGA1UEChMOUHJpdmFzcGhlcmUgQUcxEDAOBgNVBAsTB1Rlc3RpbmcxJDAiBgkq"
      + "hkiG9w0BCQEWFWFybWluQHByaXZhc3BoZXJlLmNvbTAeFw0wNzA0MDIwODQ5NTNa"
      + "Fw0xNzAzMzAwODQ0MDBaMIGNMQ8wDQYDVQQDEwZJbnRlcjExCzAJBgNVBAYTAkNI"
      + "MQ8wDQYDVQQHEwZadXJpY2gxCzAJBgNVBAgTAlpIMRcwFQYDVQQKEw5Qcml2YXNw"
      + "aGVyZSBBRzEQMA4GA1UECxMHVGVzdGluZzEkMCIGCSqGSIb3DQEJARYVYXJtaW5A"
      + "cHJpdmFzcGhlcmUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCae3TP"
      + "jIVKeASqvNabaiUHAMGUgFxB7L0yUsIj39azLcLtUj4S7XkDf7SMGtYV0JY1XNaQ"
      + "sHJAsnJivDZc50oiYvqDYfgFZx5+AsN5l5X5rjRzs/OX+Jo+k1OgsIyu6+mf9Kfb"
      + "5IdWOVB2EcOg4f9tPjLM8CIj9Pp7RbKLyqUUgwIDAQABoyMwITAPBgNVHRMBAf8E"
      + "BTADAQH/MA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQQFAAOBgQCgr9kUdWUT"
      + "Lt9UcztSzR3pnHRsyvS0E/z850OKQKS5/VxLEalpFvhj+3EcZ7Y6mFxaaS2B7vXg"
      + "2YWyqV1PRb6iF7/u9EXkpSTKGrJahwANirCa3V/HTUuPdCE2GITlnWI8h3eVA+xQ"
      + "D4LF0PXHOkXbwmhXRSb10lW1bSGkUxE9jg==");

    private void testExceptions()
        throws Exception
    {
        byte[] enc = { (byte)0, (byte)2, (byte)3, (byte)4, (byte)5 };
        MyCertPath mc = new MyCertPath(enc);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ByteArrayInputStream is;
        byte[] arr;

        ObjectOutputStream oOut = new ObjectOutputStream(os);
        oOut.writeObject(mc);
        oOut.flush();
        oOut.close();

        try
        {
            CertificateFactory cFac = CertificateFactory.getInstance("X.509",
                    "BC");
            arr = os.toByteArray();
            is = new ByteArrayInputStream(arr);
            cFac.generateCertPath(is);
        }
        catch (CertificateException e)
        {
            // ignore okay
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List certCol = new ArrayList();

        certCol.add(cf.generateCertificate(new ByteArrayInputStream(certA)));
        certCol.add(cf.generateCertificate(new ByteArrayInputStream(certB)));
        certCol.add(cf.generateCertificate(new ByteArrayInputStream(certC)));
        certCol.add(cf.generateCertificate(new ByteArrayInputStream(certD)));

        CertPathBuilder pathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector select = new X509CertSelector();
        select.setSubject(((X509Certificate)certCol.get(0)).getSubjectX500Principal().getEncoded());

        Set trustanchors = new HashSet();
        trustanchors.add(new TrustAnchor((X509Certificate)cf.generateCertificate(new ByteArrayInputStream(rootCertBin)), null));

        CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certCol));

        PKIXBuilderParameters params = new PKIXBuilderParameters(trustanchors, select);
        params.addCertStore(certStore);

        try
        {
            CertPathBuilderResult result = pathBuilder.build(params);
            CertPath path = result.getCertPath();
            fail("found cert path in circular set");
        }
        catch (CertPathBuilderException e) 
        {
            // expected
        }
    }
    
    public void performTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(rootCertBin));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(interCertBin));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(finalCertBin));

            //Testing CertPath generation from List
        List list = new ArrayList();
        list.add(interCert);
        CertPath certPath1 = cf.generateCertPath(list);

            //Testing CertPath encoding as PkiPath
        byte[] encoded = certPath1.getEncoded("PkiPath");

            //Testing CertPath generation from InputStream
        ByteArrayInputStream inStream = new ByteArrayInputStream(encoded);
        CertPath certPath2 = cf.generateCertPath(inStream, "PkiPath");

            //Comparing both CertPathes
        if (!certPath2.equals(certPath1))
        {
            fail("CertPath differ after encoding and decoding.");
        }

        encoded = certPath1.getEncoded("PKCS7");

            //Testing CertPath generation from InputStream
        inStream = new ByteArrayInputStream(encoded);
        certPath2 = cf.generateCertPath(inStream, "PKCS7");

            //Comparing both CertPathes
        if (!certPath2.equals(certPath1))
        {
            fail("CertPath differ after encoding and decoding.");
        }

        encoded = certPath1.getEncoded("PEM");

            //Testing CertPath generation from InputStream
        inStream = new ByteArrayInputStream(encoded);
        certPath2 = cf.generateCertPath(inStream, "PEM");

            //Comparing both CertPathes
        if (!certPath2.equals(certPath1))
        {
            fail("CertPath differ after encoding and decoding.");
        }

        //
        // empty list test
        //
        list = new ArrayList();

        CertPath certPath = CertificateFactory.getInstance("X.509","BC").generateCertPath(list);
        if (certPath.getCertificates().size() != 0)
        {
            fail("list wrong size.");
        }

        //
        // exception tests
        //
        testExceptions();
    }

    public String getName()
    {
        return "CertPath";
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CertPathTest());
    }

    private static class MyCertificate extends Certificate
    {
        private final byte[] encoding;

        public MyCertificate(String type, byte[] encoding)
        {
            super(type);
            // don't copy to allow null parameter in test
            this.encoding = encoding;
        }

        public byte[] getEncoded() throws CertificateEncodingException
        {
            // do copy to force NPE in test
            return (byte[])encoding.clone();
        }

        public void verify(PublicKey key) throws CertificateException,
                NoSuchAlgorithmException, InvalidKeyException,
                NoSuchProviderException, SignatureException
        {
        }

        public void verify(PublicKey key, String sigProvider)
                throws CertificateException, NoSuchAlgorithmException,
                InvalidKeyException, NoSuchProviderException,
                SignatureException
        {
        }

        public String toString()
        {
            return "[My test Certificate, type: " + getType() + "]";
        }

        public PublicKey getPublicKey()
        {
            return new PublicKey()
            {
                public String getAlgorithm()
                {
                    return "TEST";
                }

                public byte[] getEncoded()
                {
                    return new byte[] { (byte)1, (byte)2, (byte)3 };
                }

                public String getFormat()
                {
                    return "TEST_FORMAT";
                }
            };
        }
    }

    private static class MyCertPath extends CertPath
    {
        private final Vector certificates;

        private final Vector encodingNames;

        private final byte[] encoding;

        public MyCertPath(byte[] encoding)
        {
            super("MyEncoding");
            this.encoding = encoding;
            certificates = new Vector();
            certificates.add(new MyCertificate("MyEncoding", encoding));
            encodingNames = new Vector();
            encodingNames.add("MyEncoding");
        }

        public List getCertificates()
        {
            return Collections.unmodifiableList(certificates);
        }

        public byte[] getEncoded() throws CertificateEncodingException
        {
            return (byte[])encoding.clone();
        }

        public byte[] getEncoded(String encoding)
                throws CertificateEncodingException
        {
            if (getType().equals(encoding))
            {
                return (byte[])this.encoding.clone();
            }
            throw new CertificateEncodingException("Encoding not supported: "
                    + encoding);
        }

        public Iterator getEncodings()
        {
            return Collections.unmodifiableCollection(encodingNames).iterator();
        }
    }

}

