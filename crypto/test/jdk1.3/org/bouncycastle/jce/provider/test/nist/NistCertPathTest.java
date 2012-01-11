package org.bouncycastle.jce.provider.test.nist;

import java.io.FileInputStream;
import java.io.InputStream;
import org.bouncycastle.jce.cert.CertPath;
import org.bouncycastle.jce.cert.CertPathValidator;
import org.bouncycastle.jce.cert.CertPathValidatorException;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertificateFactory;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import org.bouncycastle.jce.cert.PKIXCertPathValidatorResult;
import org.bouncycastle.jce.cert.PKIXParameters;
import org.bouncycastle.jce.cert.TrustAnchor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 * NIST CertPath test data for RFC 3280
 */
public class NistCertPathTest
    extends TestCase
{
    private static final String TEST_DATA_HOME = "bc.test.data.home";

    private static final String GOOD_CA_CERT = "GoodCACert";

    private static final String GOOD_CA_CRL = "GoodCACRL";

    private static final String TRUST_ANCHOR_ROOT_CRL = "TrustAnchorRootCRL";

    private static final String TRUST_ANCHOR_ROOT_CERTIFICATE = "TrustAnchorRootCertificate";

    private static final char[] PKCS12_PASSWORD = "password".toCharArray();
    
    private static String NIST_TEST_POLICY_1 = "2.16.840.1.101.3.2.1.48.1";
    private static String NIST_TEST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";
    private static String NIST_TEST_POLICY_3 = "2.16.840.1.101.3.2.1.48.3";
    
    private static Map   certs = new HashMap();
    private static Map   crls = new HashMap();
    
    private static Set   noPolicies = Collections.EMPTY_SET;
    private static Set   nistTestPolicy1 = Collections.singleton(NIST_TEST_POLICY_1);
    private static Set   nistTestPolicy2 = Collections.singleton(NIST_TEST_POLICY_2);
    private static Set   nistTestPolicy3 = Collections.singleton(NIST_TEST_POLICY_3);
    private static Set   nistTestPolicy1And2 = new HashSet(Arrays.asList(new String[] { NIST_TEST_POLICY_1, NIST_TEST_POLICY_2 }));
    
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    public void testValidSignaturesTest1()
        throws Exception
    {
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "ValidCertificatePathTest1EE", GOOD_CA_CERT}, 
                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL });
    }
    
    public void testInvalidCASignatureTest2()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "ValidCertificatePathTest1EE", "BadSignedCACert" }, 
                new String[] { "BadSignedCACRL", TRUST_ANCHOR_ROOT_CRL},
                1,
                "TrustAnchor found but certificate validation failed.");
    }

    public void testInvalidEESignatureTest3()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
            new String[] { GOOD_CA_CERT, "InvalidEESignatureTest3EE" }, 
            new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL },
            0,
            "Could not validate certificate signature.");
    }
    
    public void testValidDSASignaturesTest4()
        throws Exception
    {
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "DSACACert", "ValidDSASignaturesTest4EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "DSACACRL" });
    }
    /*
    public void testValidDSAParameterInheritanceTest5()
        throws Exception
    {
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "DSACACert", "DSAParametersInheritedCACert", "ValidDSAParameterInheritanceTest5EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "DSACACRL", "DSAParametersInheritedCACRL" });
    }
    */
    public void testInvalidDSASignaturesTest6()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "DSACACert", "InvalidDSASignatureTest6EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "DSACACRL" },
                0,
                "Could not validate certificate signature.");
    }
    
    public void testCANotBeforeDateTest1()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "BadnotBeforeDateCACert", "InvalidCAnotBeforeDateTest1EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "BadnotBeforeDateCACRL" },
                1,
                "Could not validate certificate: certificate not valid till 20470101120100GMT+00:00");
    }
    
    public void testInvalidEENotBeforeDateTest2()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "InvalidEEnotBeforeDateTest2EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL },
                0,
                "Could not validate certificate: certificate not valid till 20470101120100GMT+00:00");
    }
    
    public void testValidPre2000UTCNotBeforeDateTest3()
        throws Exception
    {
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "Validpre2000UTCnotBeforeDateTest3EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL });
    }
    
    public void testValidGeneralizedTimeNotBeforeDateTest4()
        throws Exception
    {
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "ValidGeneralizedTimenotBeforeDateTest4EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL });
    }
    
    public void testInvalidCANotAfterDateTest5()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "BadnotAfterDateCACert", "InvalidCAnotAfterDateTest5EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "BadnotAfterDateCACRL" },
                1,
                "Could not validate certificate: certificate expired on 20020101120100GMT+00:00");
    }
    
    public void testInvalidEENotAfterDateTest6()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "InvalidEEnotAfterDateTest6EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL },
                0,
                "Could not validate certificate: certificate expired on 20020101120100GMT+00:00");
    }
    
    public void testInvalidValidPre2000UTCNotAfterDateTest7()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "Invalidpre2000UTCEEnotAfterDateTest7EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL },
                0,
                "Could not validate certificate: certificate expired on 19990101120100GMT+00:00");
    }
    
    public void testInvalidNegativeSerialNumberTest15()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "NegativeSerialNumberCACert", "InvalidNegativeSerialNumberTest15EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "NegativeSerialNumberCACRL" },
                0,
                "Certificate revocation after Fri Apr 20 00:57:20 EST 2001, reason: keyCompromise");
    }
    
    //
    // 4.8 Certificate Policies
    //
    public void testAllCertificatesSamePolicyTest1()
        throws Exception
    {
        String[] certList = new String[] { GOOD_CA_CERT, "ValidCertificatePathTest1EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                certList, 
                crlList,
                noPolicies); 
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                certList, 
                crlList,
                nistTestPolicy1);
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                certList, 
                crlList,
                nistTestPolicy2,
                -1,
                "Path processing failed on policy.");
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                certList, 
                crlList,
                nistTestPolicy1And2);
    }
    
    public void testAllCertificatesNoPoliciesTest2()
        throws Exception
    {
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "NoPoliciesCACert", "AllCertificatesNoPoliciesTest2EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "NoPoliciesCACRL" });
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "NoPoliciesCACert", "AllCertificatesNoPoliciesTest2EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "NoPoliciesCACRL" },
                noPolicies,
                -1,
                "No valid policy tree found when one expected.");
    }
    
    public void testDifferentPoliciesTest3()
        throws Exception
    {
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL" });
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL" },
                noPolicies,
                -1,
                "No valid policy tree found when one expected.");
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL" },
                nistTestPolicy1And2,
                -1,
                "No valid policy tree found when one expected.");
    }
    
    public void testDifferentPoliciesTest4()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "GoodsubCACert", "DifferentPoliciesTest4EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "GoodsubCACRL" },
                -1,
                "No valid policy tree found when one expected."); 
    }
    
    public void testDifferentPoliciesTest5()
        throws Exception
    {
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "PoliciesP2subCA2Cert", "DifferentPoliciesTest5EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCA2CRL" },
                -1,
                "No valid policy tree found when one expected."); 
    }
    
    public void testOverlappingPoliciesTest6()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP1234CACert", "PoliciesP1234subCAP123Cert", "PoliciesP1234subsubCAP123P12Cert", "OverlappingPoliciesTest6EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP1234CACRL", "PoliciesP1234subCAP123CRL", "PoliciesP1234subsubCAP123P12CRL" };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "Path processing failed on policy.");
    }
    
    public void testDifferentPoliciesTest7()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP123CACert", "PoliciesP123subCAP12Cert", "PoliciesP123subsubCAP12P1Cert", "DifferentPoliciesTest7EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL", "PoliciesP123subCAP12CRL", "PoliciesP123subsubCAP12P1CRL" };
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList,
                -1,
                "No valid policy tree found when one expected."); 
    }
    
    public void testDifferentPoliciesTest8()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP12CACert", "PoliciesP12subCAP1Cert", "PoliciesP12subsubCAP1P2Cert", "DifferentPoliciesTest8EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL", "PoliciesP12subCAP1CRL", "PoliciesP12subsubCAP1P2CRL" };
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList,
                -1,
                "No valid policy tree found when one expected.");
    }
    
    public void testDifferentPoliciesTest9()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP123CACert", "PoliciesP123subCAP12Cert", "PoliciesP123subsubCAP12P2Cert", "PoliciesP123subsubsubCAP12P2P1Cert", "DifferentPoliciesTest9EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL", "PoliciesP123subCAP12CRL", "PoliciesP123subsubCAP2P2CRL", "PoliciesP123subsubsubCAP12P2P1CRL" };
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList,
                -1,
                "No valid policy tree found when one expected.");
    }
    
    public void testAllCertificatesSamePoliciesTest10()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP12CACert", "AllCertificatesSamePoliciesTest10EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL" };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
    }
    
    public void testAllCertificatesAnyPolicyTest11()
        throws Exception
    {
        String[] certList = new String[] { "anyPolicyCACert", "AllCertificatesanyPolicyTest11EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "anyPolicyCACRL" };
        
        PKIXCertPathValidatorResult result = doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);

        result = doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
    }
    
    public void testDifferentPoliciesTest12()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP3CACert", "DifferentPoliciesTest12EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP3CACRL" };
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList,
                -1,
                "No valid policy tree found when one expected.");
    }
    
    public void testAllCertificatesSamePoliciesTest13()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP123CACert", "AllCertificatesSamePoliciesTest13EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL" };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy3);
    }
    
    public void testAnyPolicyTest14()
        throws Exception
    {
        String[] certList = new String[] { "anyPolicyCACert", "AnyPolicyTest14EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "anyPolicyCACRL" };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "Path processing failed on policy.");
    }
    
    public void testUserNoticeQualifierTest15()
        throws Exception
    {
        String[] certList = new String[] { "UserNoticeQualifierTest15EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "Path processing failed on policy.");
    }
    
    public void testUserNoticeQualifierTest16()
        throws Exception
    {
        String[] certList = new String[] { GOOD_CA_CERT, "UserNoticeQualifierTest16EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL };
        
        PKIXCertPathValidatorResult result = doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        
        result = doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "Path processing failed on policy.");
    }
    
    public void testUserNoticeQualifierTest17()
        throws Exception
    {
        String[] certList = new String[] { GOOD_CA_CERT, "UserNoticeQualifierTest17EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "Path processing failed on policy.");
    }
    
    public void testUserNoticeQualifierTest18()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP12CACert", "UserNoticeQualifierTest18EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL" };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
    }
    
    public void testUserNoticeQualifierTest19()
        throws Exception
    {
        String[] certList = new String[] { "UserNoticeQualifierTest19EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL };
        
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doExceptionTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "Path processing failed on policy.");
    }

    private void doExceptionTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        int         index,
        String      message)
        throws Exception
    {
        try
        {
            doTest(trustAnchor, certs, crls);
            
            fail("path accepted when should be rejected");
        }
        catch (CertPathValidatorException e)
        {
            assertEquals(index, e.getIndex());
            assertEquals(message, e.getMessage());
        }
    }
    
    private void doExceptionTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        Set         policies,
        int         index,
        String      message)
        throws Exception
    {
        try
        {
            doTest(trustAnchor, certs, crls, policies);
            
            fail("path accepted when should be rejected");
        }
        catch (CertPathValidatorException e)
        {
            assertEquals(index, e.getIndex());
            assertTrue(message.equals(e.getMessage()));
        }
    }
    
    private PKIXCertPathValidatorResult doTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls)
        throws Exception
    {
        return doTest(trustAnchor, certs, crls, null);
    }
    
    private PKIXCertPathValidatorResult doTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        Set         policies)
        throws Exception
    {
        Set  trustedSet = Collections.singleton(getTrustAnchor(trustAnchor));
        List certsAndCrls = new ArrayList();
        X509Certificate endCert = loadCert(certs[certs.length - 1]);
        
        for (int i = 0; i != certs.length - 1; i++)
        {
            certsAndCrls.add(loadCert(certs[i]));
        }
        
        certsAndCrls.add(endCert);
    
        CertPath certPath = CertificateFactory.getInstance("X.509","BC").generateCertPath(certsAndCrls);
    
        for (int i = 0; i != crls.length; i++)
        {
            certsAndCrls.add(loadCrl(crls[i]));
        }
    
        CertStore  store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCrls), "BC");
        
        CertPathValidator validator = CertPathValidator.getInstance("PKIX","BC");
        PKIXParameters    params = new PKIXParameters(trustedSet);
        
        params.addCertStore(store);
        params.setRevocationEnabled(true);
        
        if (policies != null)
        {
            params.setExplicitPolicyRequired(true);
            params.setInitialPolicies(policies);
        }
        
        return (PKIXCertPathValidatorResult)validator.validate(certPath, params);
    }

    private X509Certificate loadCert(
        String certName)
    {
        X509Certificate cert = (X509Certificate)certs.get(certName);
        
        if (cert != null)
        {
            return cert;
        }
        
        try
        {
            InputStream in = new FileInputStream(getPkitsHome() + "/certs/" + certName + ".crt");
            
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
            
            cert = (X509Certificate)fact.generateCertificate(in);
    
            certs.put(certName, cert);
            
            return cert;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception loading certificate: " + certName);
        }
    }
    
    private X509CRL loadCrl(
        String crlName)
        throws Exception
    {
        X509CRL crl = (X509CRL)certs.get(crlName);
        
        if (crl != null)
        {
            return crl;
        }
        
        try
        {
            InputStream in = new FileInputStream(getPkitsHome() + "/crls/" + crlName + ".crl");
            
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
            
            crl = (X509CRL)fact.generateCRL(in);
            
            crls.put(crlName, crl);
            
            return crl;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception loading CRL: " + crlName);
        }
    }

    private TrustAnchor getTrustAnchor(String trustAnchorName)
        throws Exception
    {
        X509Certificate cert = loadCert(trustAnchorName);
        byte[]          extBytes = cert.getExtensionValue(X509Extensions.NameConstraints.getId());
        
        if (extBytes != null)
        {
            ASN1Encodable extValue = X509ExtensionUtil.fromExtensionValue(extBytes);
            
            return new TrustAnchor(cert, extValue.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        }
        
        return new TrustAnchor(cert, null);
    }
    
    private String getPkitsHome()
    {
        String dataHome = System.getProperty(TEST_DATA_HOME);
        
        if (dataHome == null)
        {
            throw new IllegalStateException(TEST_DATA_HOME + " property not set");
        }
        
        return dataHome + "/PKITS";
    }
    
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("NIST Tests");
        Security.addProvider(new BouncyCastleProvider());
        suite.addTestSuite(NistCertPathTest.class);
        
        return suite;
    }
}
