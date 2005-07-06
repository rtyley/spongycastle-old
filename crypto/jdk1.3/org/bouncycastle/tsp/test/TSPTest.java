package org.bouncycastle.tsp.test;

import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.cert.CertStore;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;

public class TSPTest
    implements Test
{
    /* (non-Javadoc)
     * @see org.bouncycastle.util.test.Test#getName()
     */
    public String getName()
    {
        return "TSPTest";
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.util.test.Test#perform()
     */
    public TestResult perform()
    {
        try
        {
            String signDN = "O=Bouncy Castle, C=AU";
            KeyPair signKP = TSPTestUtil.makeKeyPair();
            X509Certificate signCert = TSPTestUtil.makeCACertificate(signKP,
                    signDN, signKP, signDN);

            String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
            KeyPair origKP = TSPTestUtil.makeKeyPair();
            X509Certificate origCert = TSPTestUtil.makeCertificate(origKP,
                    origDN, signKP, signDN);


            
            java.util.ArrayList certList = new java.util.ArrayList();
            certList.add(origCert);
            certList.add(signCert);

            CertStore certs = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certList), "BC");
            
            TestResult  res = basicTest(origKP.getPrivate(), origCert, certs);
            if (!res.isSuccessful())
            {
                return res;
            }
            
            res = responseValidationTest(origKP.getPrivate(), origCert, certs);
            if (!res.isSuccessful())
            {
                return res;
            }
            
            res = incorrectHashTest(origKP.getPrivate(), origCert, certs);
            if (!res.isSuccessful())
            {
                return res;
            }
            
            res = badAlgorithmTest(origKP.getPrivate(), origCert, certs);
            if (!res.isSuccessful())
            {
                return res;
            }
            
            res = badPolicyTest(origKP.getPrivate(), origCert, certs);
            if (!res.isSuccessful())
            {
                return res;
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Exception - " + e.toString(), e);
        }
    }
    
    public TestResult basicTest(
        PrivateKey      privateKey,
        X509Certificate cert,
        CertStore       certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                privateKey, cert, TSPAlgorithms.SHA1, "1.2");
        
        tsTokenGen.setCertificatesAndCRLs(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest          request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(), "BC");

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken  tsToken = tsResp.getTimeStampToken();

        try
        {
            tsToken.validate(cert, "BC");
        }
        catch (TSPValidationException e)
        {
            return new SimpleTestResult(false, getName() + ": validation of token failed.");
        }

        AttributeTable  table = tsToken.getSignedAttributes();

        if (table.get(PKCSObjectIdentifiers.id_aa_signingCertificate) == null)
        {
            return new SimpleTestResult(false, getName() + ": no signingCertificate attribute found.");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult responseValidationTest(
        PrivateKey      privateKey,
        X509Certificate cert,
        CertStore       certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                privateKey, cert, TSPAlgorithms.MD5, "1.2");
        
        tsTokenGen.setCertificatesAndCRLs(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest          request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(), "BC");

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken  tsToken = tsResp.getTimeStampToken();

        try
        {
            tsToken.validate(cert, "BC");
        }
        catch (TSPValidationException e)
        {
            return new SimpleTestResult(false, getName() + ": verification of token failed in response validation.");
        }
        
        //
        // check validation
        //
        try
        {
            tsResp.validate(request);
        }
        catch (TSPValidationException e)
        {
            return new SimpleTestResult(false, getName() + ": response validation failed - " + e.getMessage());
        }
        
        try
        {
            request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(101));
            
            tsResp.validate(request);
            
            return new SimpleTestResult(false, getName() + ": response validation failed on invalid nonce.");
        }
        catch (TSPValidationException e)
        {
            // ignore
        }

        try
        {
            request = reqGen.generate(TSPAlgorithms.SHA1, new byte[22], BigInteger.valueOf(100));
            
            tsResp.validate(request);
            
            return new SimpleTestResult(false, getName() + ": response validation failed on wrong digest.");
        }
        catch (TSPValidationException e)
        {
            // ignore
        }
        
        try
        {
            request = reqGen.generate(TSPAlgorithms.MD5, new byte[20], BigInteger.valueOf(100));
            
            tsResp.validate(request);
            
            return new SimpleTestResult(false, getName() + ": response validation failed on wrong digest.");
        }
        catch (TSPValidationException e)
        {
            // ignore
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult incorrectHashTest(
        PrivateKey      privateKey,
        X509Certificate cert,
        CertStore       certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                privateKey, cert, TSPAlgorithms.SHA1, "1.2");
        
        tsTokenGen.setCertificatesAndCRLs(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest            request = reqGen.generate(TSPAlgorithms.SHA1, new byte[16]);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(), "BC");

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken  tsToken = tsResp.getTimeStampToken();

        if (tsToken != null)
        {
            return new SimpleTestResult(false, getName() + ": incorrectHash - token not null.");
        }
        
        PKIFailureInfo  failInfo = tsResp.getFailInfo();
        
        if (failInfo == null)
        {
            return new SimpleTestResult(false, getName() + ": incorrectHash - failInfo set to null.");
        }
        
        if (failInfo.intValue() != PKIFailureInfo.BAD_DATA_FORMAT)
        {
            return new SimpleTestResult(false, getName() + ": incorrectHash - wrong failure info returned.");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult badAlgorithmTest(
        PrivateKey      privateKey,
        X509Certificate cert,
        CertStore       certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                privateKey, cert, TSPAlgorithms.SHA1, "1.2");
        
        tsTokenGen.setCertificatesAndCRLs(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest            request = reqGen.generate("1.2.3.4.5", new byte[20]);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(), "BC");

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken  tsToken = tsResp.getTimeStampToken();

        if (tsToken != null)
        {
            return new SimpleTestResult(false, getName() + ": badAlgorithm - token not null.");
        }

        PKIFailureInfo  failInfo = tsResp.getFailInfo();
        
        if (failInfo == null)
        {
            return new SimpleTestResult(false, getName() + ": badAlgorithm - failInfo set to null.");
        }
        
        if (failInfo.intValue() != PKIFailureInfo.BAD_ALG)
        {
            return new SimpleTestResult(false, getName() + ": badAlgorithm - wrong failure info returned.");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult badPolicyTest(
        PrivateKey      privateKey,
        X509Certificate cert,
        CertStore       certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                privateKey, cert, TSPAlgorithms.SHA1, "1.2");
        
        tsTokenGen.setCertificatesAndCRLs(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        
        reqGen.setReqPolicy("4.4");
        
        TimeStampRequest            request = reqGen.generate(TSPAlgorithms.SHA1, new byte[20]);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED, new HashSet());

        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(), "BC");

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken  tsToken = tsResp.getTimeStampToken();

        if (tsToken != null)
        {
            return new SimpleTestResult(false, getName() + ": badPolicy - token not null.");
        }

        PKIFailureInfo  failInfo = tsResp.getFailInfo();
        
        if (failInfo == null)
        {
            return new SimpleTestResult(false, getName() + ": badPolicy - failInfo set to null.");
        }
        
        if (failInfo.intValue() != PKIFailureInfo.UNACCEPTED_POLICY)
        {
            return new SimpleTestResult(false, getName() + ": badPolicy - wrong failure info returned.");
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult certReqTest(
        PrivateKey      privateKey,
        X509Certificate cert,
        CertStore       certs)
        throws Exception
    {
        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                privateKey, cert, TSPAlgorithms.SHA1, "1.2");
        
        tsTokenGen.setCertificatesAndCRLs(certs);

        TimeStampRequestGenerator   reqGen = new TimeStampRequestGenerator();
        
        //
        // request with certReq false
        //
        reqGen.setCertReq(false);
        
        TimeStampRequest            request = reqGen.generate("1.2.3.4.5", new byte[20]);

        TimeStampResponseGenerator  tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        TimeStampResponse           tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(), "BC");

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        TimeStampToken  tsToken = tsResp.getTimeStampToken();

        try
        {
            tsToken.validate(cert, "BC");
        }
        catch (TSPValidationException e)
        {
            return new SimpleTestResult(false, getName() + ": certReq(false) verification of token failed.");
        }

        CertStore   respCerts = tsToken.getCertificatesAndCRLs("Collection", "BC");
        
        Collection  certsColl = respCerts.getCertificates(null);
        
        if (!certsColl.isEmpty())
        {
            return new SimpleTestResult(false, getName() + ": certReq(false) found certificates in response.");
        }
        
        //
        // request with certReq true
        //
        reqGen.setCertReq(true);
        
        request = reqGen.generate("1.2.3.4.5", new byte[20]);

        tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);

        tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date(), "BC");

        tsResp = new TimeStampResponse(tsResp.getEncoded());

        tsToken = tsResp.getTimeStampToken();

        try
        {
            tsToken.validate(cert, "BC");
        }
        catch (TSPValidationException e)
        {
            return new SimpleTestResult(false, getName() + ": certReq(true) verification of token failed.");
        }
        
        if (certsColl.isEmpty())
        {
            return new SimpleTestResult(false, getName() + ": certReq(false) no certificates found.");
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new TSPTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
