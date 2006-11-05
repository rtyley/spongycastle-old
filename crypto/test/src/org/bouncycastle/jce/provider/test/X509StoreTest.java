package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509AttributeCertStoreSelector;
import org.bouncycastle.x509.X509CRLStoreSelector;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.X509CollectionStoreParameters;
import org.bouncycastle.x509.X509Store;
import org.bouncycastle.x509.X509V2AttributeCertificate;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
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
        X509CertStoreSelector targetConstraints = new X509CertStoreSelector();
        targetConstraints.setSubject(rootCert.getSubjectX500Principal()
                .getName());
        Collection certs = store.getMatches(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by subjectDN");
        }

        // Searching for rootCert by subjectDN encoded as byte
        targetConstraints = new X509CertStoreSelector();
        targetConstraints.setSubject(rootCert.getSubjectX500Principal()
                .getEncoded());
        certs = store.getMatches(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by encoded subjectDN");
        }

        // Searching for rootCert by public key encoded as byte
        targetConstraints = new X509CertStoreSelector();
        targetConstraints.setSubjectPublicKey(rootCert.getPublicKey()
                .getEncoded());
        certs = store.getMatches(targetConstraints);
        if (certs.size() != 1 || !certs.contains(rootCert))
        {
            fail("rootCert not found by encoded public key");
        }

        // Searching for interCert by issuerDN
        targetConstraints = new X509CertStoreSelector();
        targetConstraints.setIssuer(rootCert.getSubjectX500Principal()
                .getEncoded());
        certs = store.getMatches(targetConstraints);
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
        X509CRLStoreSelector targetConstraintsCRL = new X509CRLStoreSelector();
        targetConstraintsCRL.addIssuerName(rootCrl.getIssuerX500Principal()
                .getEncoded());
        Collection crls = store.getMatches(targetConstraintsCRL);
        if (crls.size() != 1 || !crls.contains(rootCrl))
        {
            fail("rootCrl not found");
        }

        // Searching for attribute certificates
        X509V2AttributeCertificate attrCert = new X509V2AttributeCertificate(AttrCertTest.attrCert);

        List attrList = new ArrayList();
        attrList.add(attrCert);
        ccsp = new X509CollectionStoreParameters(attrList);
        store = X509Store.getInstance("AttributeCertificate/Collection", ccsp, "BC");
        X509AttributeCertStoreSelector attrSelector = new X509AttributeCertStoreSelector();
        attrSelector.setHolder(attrCert.getHolder());
        Collection attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found");
        }
        attrSelector.setIssuer(attrCert.getIssuer());
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found");
        }
        attrSelector.setAttributeCert(attrCert);
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found");
        }
        attrSelector.setSerialNumber(attrCert.getSerialNumber());
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found");
        }
        attrSelector.setAttributeCertificateValid(attrCert.getNotBefore());
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 1 || !attrs.contains(attrCert))
        {
            fail("attrCert not found");
        }
        attrSelector.setAttributeCertificateValid(new Date(attrCert.getNotBefore().getTime() - 100));
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 0)
        {
            fail("attrCert found on before");
        }
        attrSelector.setAttributeCertificateValid(new Date(attrCert.getNotAfter().getTime() + 100));
        attrs = store.getMatches(attrSelector);
        if (attrs.size() != 0)
        {
            fail("attrCert found on after");
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
