
package org.bouncycastle.mail.smime.examples;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.validator.SignedMailValidator;
import org.bouncycastle.x509.PKIXCertPathReviewer;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 * An Example that reads a signed mail and validates its signature. Also validating the certificate
 * path from the signers key to a trusted entity
 */
public class ValidateSignedMail
{
    
    public static void main(String[] args) throws Exception
    {
        
        Security.addProvider(new BouncyCastleProvider());
        
        //
        // Get a Session object with the default properties.
        //
        Properties props = System.getProperties();

        Session session = Session.getDefaultInstance(props, null);
        
        
        // read message
        MimeMessage msg = new MimeMessage(session, new FileInputStream("signed.message"));
        
        // read trustanchors
        Set trustanchors = new HashSet();
        trustanchors.add(getTrustAnchor("trustanchor"));
        
        // read crls
        List crls = new ArrayList();
        crls.add(loadCRL("crl.file"));
        CertStore certStore = CertStore.getInstance("Collection",new CollectionCertStoreParameters(crls),"BC");
        
        // create PKIXparameters
        PKIXParameters param = new PKIXParameters(trustanchors);
        // add crls
        param.addCertStore(certStore);
        param.setRevocationEnabled(true);
        
        verifySignedMail(msg,param);
    }
    
    protected static TrustAnchor getTrustAnchor(String trustcert) throws Exception
    {
        X509Certificate cert = loadCert(trustcert);
        byte[] ncBytes = cert.getExtensionValue(X509Extensions.NameConstraints.getId());
        
        if (ncBytes != null)
        {
            ASN1Encodable extValue = X509ExtensionUtil.fromExtensionValue(ncBytes);
            return new TrustAnchor(cert,extValue.getDEREncoded());
        }
        return new TrustAnchor(cert,null);
    }
    
    protected static X509Certificate loadCert(String certfile) throws Exception
    {
        InputStream in = new FileInputStream(certfile);
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
        return cert;
    }
    
    protected static X509CRL loadCRL(String crlfile) throws Exception
    {
        InputStream in = new FileInputStream(crlfile);
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
        X509CRL crl = (X509CRL) cf.generateCRL(in);
        return crl;
    }
    
    public static void verifySignedMail(MimeMessage msg,PKIXParameters param) throws Exception 
    {
        // validate signatures
        SignedMailValidator validator = new SignedMailValidator(msg,param);
        
        // iterate over all signatures and print results
        Iterator it = validator.getSignerInformationStore().getSigners().iterator();
        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation) it.next();
            SignedMailValidator.ValidationResult result = validator.getValidationResult(signer);
            if (result.isValidSignature())
            {
                System.out.println("Signature valid");
            }
            else
            {
                System.out.println("Signature invalid");
                // print errors
                System.out.println("Errors:");
                Iterator errorsIt = result.getErrors().iterator();
                while (errorsIt.hasNext())
                {
                    ErrorBundle errorMsg = (ErrorBundle) errorsIt.next();
                    System.out.println("\t" + errorMsg.getText(Locale.ENGLISH));
                }
            }
            PKIXCertPathReviewer review = result.getCertPathReview();
            if (review != null)
            {
                if (review.isValidCertPath())
                {
                    System.out.println("Certificate path valid");
                }
                else
                {
                    System.out.println("Certificate path invalid");
                }
                
                System.out.println("\nCertificate path validation results:");
                // global errors
                System.out.println("Errors:");
                Iterator errorsIt = review.getErrors(-1).iterator();
                while (errorsIt.hasNext())
                {
                    ErrorBundle errorMsg = (ErrorBundle) errorsIt.next();
                    System.out.println("\t" + errorMsg.getText(Locale.ENGLISH));
                }
                
                System.out.println("Notifications:");
                Iterator notificationsIt = review.getNotifications(-1).iterator();
                while (notificationsIt.hasNext())
                {
                    ErrorBundle noteMsg = (ErrorBundle) notificationsIt.next();
                    System.out.println("\t" + noteMsg.getText(Locale.ENGLISH));
                }
                
                // per certificate errors and notifications
                Iterator certIt = review.getCertPath().getCertificates().iterator();
                int i = 0;
                while (certIt.hasNext())
                {
                    X509Certificate cert = (X509Certificate) certIt.next();
                    System.out.println("Certificate " + i);
                    System.out.println("Issuer: " + cert.getIssuerDN().getName());
                    System.out.println("Subject: " + cert.getSubjectDN().getName());
    
                    // errors
                    System.out.println("\tErrors:");
                    errorsIt = review.getErrors(i).iterator();
                    while (errorsIt.hasNext())
                    {
                        ErrorBundle errorMsg = (ErrorBundle) errorsIt.next();
                        System.out.println("\t\t" + errorMsg.getText(Locale.ENGLISH));
                    }
                    
                    // notifications
                    System.out.println("\tNotifications:");
                    notificationsIt = review.getNotifications(i).iterator();
                    while (notificationsIt.hasNext())
                    {
                        ErrorBundle noteMsg = (ErrorBundle) notificationsIt.next();
                        System.out.println("\t\t" + noteMsg.getText(Locale.ENGLISH));
                    }
                    
                    i++;
                }
            }
        }
        
    }
    
}
