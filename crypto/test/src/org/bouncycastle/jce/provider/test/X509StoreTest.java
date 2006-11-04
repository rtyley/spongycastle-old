package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509CRLSelectorWrapper;
import org.bouncycastle.x509.X509CertSelectorWrapper;
import org.bouncycastle.x509.X509CollectionStoreParameters;
import org.bouncycastle.x509.X509Store;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class X509StoreTest
    extends SimpleTest
{

    public void performTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509",
                "BC");

        X509Certificate rootCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf
                .generateCertificate(new ByteArrayInputStream(
                        CertPathTest.finalCertBin));
        X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(
                CertPathTest.rootCrlBin));
        X509CRL interCrl = (X509CRL)cf
                .generateCRL(new ByteArrayInputStream(
                        CertPathTest.interCrlBin));

        // Testing CollectionCertStore generation from List
        List certList = new ArrayList();
        certList.add(rootCert);
        certList.add(interCert);
        certList.add(finalCert);
        X509CollectionStoreParameters ccsp = new X509CollectionStoreParameters(certList);
        X509Store store = X509Store.getInstance("Certificate/Collection", ccsp, "BC");

        // Searching for rootCert by subjectDN
        X509CertSelector targetConstraints = new X509CertSelector();
        targetConstraints.setSubject(rootCert.getSubjectX500Principal()
                .getName());
        Collection certs = store.getMatches(new X509CertSelectorWrapper(targetConstraints));
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by subjectDN");
        }

        // Searching for rootCert by subjectDN encoded as byte
        targetConstraints = new X509CertSelector();
        targetConstraints.setSubject(rootCert.getSubjectX500Principal()
                .getEncoded());
        certs = store.getMatches(new X509CertSelectorWrapper(targetConstraints));
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by encoded subjectDN");
        }

        // Searching for rootCert by public key encoded as byte
        targetConstraints = new X509CertSelector();
        targetConstraints.setSubjectPublicKey(rootCert.getPublicKey()
                .getEncoded());
        certs = store.getMatches(new X509CertSelectorWrapper(targetConstraints));
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by encoded public key");
        }

        // Searching for interCert by issuerDN
        targetConstraints = new X509CertSelector();
        targetConstraints.setIssuer(rootCert.getSubjectX500Principal()
                .getEncoded());
        certs = store.getMatches(new X509CertSelectorWrapper(targetConstraints));
        if (certs.size() != 2)
        {
            fail("did not found 2 certs");
        }
        if (!certs.contains(rootCert))
        {
            fail("rootCert not found");
        }
        if (!certs.contains(interCert))
        {
            fail("interCert not found");
        }

        // Searching for rootCrl by issuerDN
        List crlList = new ArrayList();
        crlList.add(rootCrl);
        crlList.add(interCrl);
        ccsp = new X509CollectionStoreParameters(crlList);
        store = X509Store.getInstance("CRL/Collection", ccsp, "BC");
        X509CRLSelector targetConstraintsCRL = new X509CRLSelector();
        targetConstraintsCRL.addIssuerName(rootCrl.getIssuerX500Principal()
                .getEncoded());
        Collection crls = store.getMatches(new X509CRLSelectorWrapper(targetConstraintsCRL));
        if (crls.size() != 1 || !crls.contains(rootCrl))
        {
            fail("rootCrl not found");
        }
    }

    public String getName()
    {
        return "X509Store";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new X509StoreTest());
    }

}
