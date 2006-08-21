
package org.bouncycastle.mail.smime.validator;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.PKIXCertPathReviewer;

public class SignedMailValidator
{
    private static final String RESOURCE_NAME = "org.bouncycastle.mail.smime.validator.SignedMailValidatorMessages";
    
    private CertStore certs;
    private SignerInformationStore signers;
    
    private Map results;
    
    /**
     * Validates the signed {@link MimeMessage} message. The {@link PKIXParameters} from param
     * are used for the certificate path validation. The actual PKIXParameters used for the certificate
     * path validation is a copy of param with the followin changes: <br>
     * - The validation date is changed to the signature time 
     * - A CertStore with certificates and crls from the mail message is added to the CertStores  
     * @param message the signed MimeMessage
     * @param param the parameters for the certificate path validation
     * @throws SignedMailValidatorException if the message is no signed message 
     * or if an exception occurs reading the message
     */
    public SignedMailValidator(MimeMessage message, PKIXParameters param) 
        throws SignedMailValidatorException
    {
        SMIMESigned s;
        
        try
        {
            // check if message is multipart signed
            if (message.isMimeType("multipart/signed")) 
            {
                MimeMultipart mimemp = (MimeMultipart) message.getContent();
                s = new SMIMESigned(mimemp);
            }
            else if (message.isMimeType("application/pkcs7-mime")
                    || message.isMimeType("application/x-pkcs7-mime"))
            {
                s = new SMIMESigned(message);
            }
            else
            {
                ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.noSignedMessage");
                throw new SignedMailValidatorException(msg);
            }
            
            // save certstore and signerInformationStore
            certs = s.getCertificatesAndCRLs("Collection","BC");
            signers = s.getSignerInfos();
            
            // initialize results
            results = new HashMap();
        }
        catch (Exception e)
        {
            if (e instanceof SignedMailValidatorException)
            {
                throw (SignedMailValidatorException) e;
            }
            // exception reading message
            ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.exceptionReadingMessage",
                    new Object[] {e.getMessage()});
            throw new SignedMailValidatorException(msg,e);
        }
        
        // validate signatues
        validateSignatures(param);
    }
    
    protected void validateSignatures(PKIXParameters pkixParam)
    {
        PKIXParameters usedParameters = (PKIXParameters) pkixParam.clone();
        
        // add crls and certs from mail
        usedParameters.addCertStore(certs);
        
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        
        // check each signer
        while (it.hasNext())
        {
            List errors = new ArrayList();
            
            SignerInformation signer = (SignerInformation) it.next();
            // signer certificate
            X509Certificate cert = null;
            
            try
            {
                Collection certCollection = certs.getCertificates(signer.getSID());
            
                Iterator        certIt = certCollection.iterator();
                cert = (X509Certificate)certIt.next();
            }
            catch (CertStoreException cse)
            {
                ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.exceptionRetrievingSignerCert",
                        new Object[] {cse.getMessage()});
                errors.add(msg);
            }
            
            if (cert != null)
            {
                // check signature
                boolean validSignature = false;
                try
                {
                    validSignature = signer.verify(cert.getPublicKey(),"BC");
                    if (!validSignature)
                    {
                        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.signatureNotVerified");
                        errors.add(msg);
                    }
                }
                catch (Exception e)
                {
                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.exceptionVerifyingSignature",
                            new Object[] {e.getMessage()});
                    errors.add(msg);
                }
                
                // check key usage if signing is permitted
                boolean[] keyUsage = cert.getKeyUsage();
                if (keyUsage != null && !keyUsage[0])
                {
                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.signingNotPermitted");
                    errors.add(msg);
                    validSignature = false;
                }
                
                // check certificate path
                
                // get signing time if possible, otherwise use current time as signing time 
                Date signTime = getSignatureTime(signer);
                if (signTime == null) // no signing time was found
                {
                    signTime = new Date();
                }
                usedParameters.setDate(signTime);
                
                try
                {
                    // construct cert chain
                    CertPath certPath;
                    try
                    {
                        // try to use the PKIXCertPathBuilder to create a cert path
                        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX","BC");
                        X509CertSelector select = new X509CertSelector();
                        select.setCertificate(cert);
                        PKIXBuilderParameters param = new PKIXBuilderParameters(usedParameters.getTrustAnchors(),select);
                        param.setDate(usedParameters.getDate());
                        param.addCertStore(certs);
                        certPath = builder.build(param).getCertPath();
                    }
                    catch (Exception e)
                    {
                        // use the backup procedure to build a cert path
                        certPath = createCertPath(cert,usedParameters.getTrustAnchors());
                    }
                    
                    // validate cert chain
                    PKIXCertPathReviewer review  = new PKIXCertPathReviewer(certPath,usedParameters);
                    if (!review.isValidCertPath())
                    {
                        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.certPathInvalid");
                        errors.add(msg);
                    }
                    results.put(signer,new ValidationResult(review,validSignature,errors));
                }
                catch (GeneralSecurityException gse)
                {
                    // cannot create cert path
                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.exceptionCreateCertPath",
                            new Object[] {gse.getMessage()});
                    errors.add(msg);
                    results.put(signer,new ValidationResult(null,validSignature,errors));
                }
                catch (CertPathReviewerException cpre)
                {
                    // cannot initialize certpathreviewer - wrong parameters
                    errors.add(cpre.getErrorMessage());
                    results.put(signer,new ValidationResult(null,validSignature,errors));
                }
            }
            else // no signer certificate found
            {
                ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,"SignedMailValidator.noSignerCert");
                results.put(signer,new ValidationResult(null,false,errors));
            }
        }
    }
    
    protected Date getSignatureTime(SignerInformation signer)
    {
        AttributeTable atab = signer.getSignedAttributes();
        Date result = null;
        if (atab != null)
        {
            Attribute attr = atab.get(CMSAttributes.signingTime);
            if (attr != null)
            {
                Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0).getDERObject());
                result = t.getDate();
            }
        }
        return result;
    }
    
    protected CertPath createCertPath(
            X509Certificate signerCert,
            Set trustanchors)
    throws GeneralSecurityException
    {
        List certList = new ArrayList();
        int maxLenght = certs.getCertificates(null).size();
        
        // add signer certificate
        
        X509Certificate cert = signerCert;
        certList.add(cert);

        boolean trustAnchorFound = false;
        
        // add other certs to the cert path
        while (cert != null && !trustAnchorFound && certList.size() < maxLenght)
        {
            // check if cert Issuer is Trustanchor
            Iterator trustIt = trustanchors.iterator();
            while (trustIt.hasNext())
            {
                TrustAnchor anchor = (TrustAnchor) trustIt.next();
                X509Certificate anchorCert = anchor.getTrustedCert();
                if (anchorCert != null)
                {
                    if (anchorCert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()))
                    {
                        try
                        {
                            cert.verify(anchorCert.getPublicKey(),"BC");
                            trustAnchorFound = true;
                            break;
                        }
                        catch (Exception e)
                        {
                            // trustanchor not found
                        }
                    }
                }
                else
                {
                    if (anchor.getCAName().equals(cert.getIssuerX500Principal().getName()))
                    {
                        try
                        {
                            cert.verify(anchor.getCAPublicKey(),"BC");
                            trustAnchorFound = true;
                            break;
                        }
                        catch (Exception e)
                        {
                            // trustanchor not found
                        }
                    }
                }
            }
            
            // add next cert to path
            X509CertSelector select = new X509CertSelector();
            try
            {
                select.setSubject(cert.getIssuerX500Principal().getEncoded());
            }
            catch (IOException e)
            {
                throw new GeneralSecurityException("exception encoding issuer: " + e);
            }
            Iterator certIt = certs.getCertificates(select).iterator();
            
            if (certIt.hasNext()) 
            {
                cert = (X509Certificate) certIt.next();
                if (!trustAnchorFound)
                {
                    certList.add(cert);
                }
                else if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal()))
                {
                    certList.add(cert);
                }
            }
            else
            {
                // no cert or trustanchor cert found -> stop
                cert = null;
            }
        }

        CertPath certPath = CertificateFactory.getInstance("X.509","BC").generateCertPath(certList);
        return certPath;
    }
    
    public CertStore getCertsAndCRLs()
    {
        return certs;
    }

    public SignerInformationStore getSignerInformationStore()
    {
        return signers;
    }
    
    public ValidationResult getValidationResult(SignerInformation signer)
    {
        if (signers.getSigners(signer.getSID()).isEmpty())
        {
            return null;
        }
        else
        {
            return (ValidationResult) results.get(signer);
        }
    }
    
    public class ValidationResult
    {
        
        private PKIXCertPathReviewer review;
        private List errors;
        private boolean signVerified;
        
        ValidationResult(PKIXCertPathReviewer review, boolean verified, List errors)
        {
            this.review = review;
            this.errors = errors;
            signVerified = verified;
        }

        /**
         * Returns a list of error messages of type {@link ErrorBundle}.
         * @return List of error messages
         */
        public List getErrors()
        {
            return errors;
        }
        
        /**
         * 
         * @return the PKIXCertPathReviewer for the CertPath of this signature or null if an
         * Exception occured.
         */
        public PKIXCertPathReviewer getCertPathReview()
        {
            return review;
        }

        /**
         * 
         * @return true if the signature corresponds to the public key of the signer
         */
        public boolean isVerifiedSignature()
        {
            return signVerified;
        }
        
        /**
         * 
         * @return true if the signature is valid (ie. if it corresponds to the 
         * public key of the signer and the cert path for the signers certificate is also valid)
         */
        public boolean isValidSignature()
        {
            if (review != null)
            {
                return signVerified && review.isValidCertPath();
            }
            else
            {
                return false;
            }
        }
        
    }
}
