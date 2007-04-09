package org.bouncycastle.mail.smime.validator;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.filter.UntrustedInput;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.PKIXCertPathReviewer;

import javax.mail.Address;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

public class SignedMailValidator
{
    private static final String RESOURCE_NAME = "org.bouncycastle.mail.smime.validator.SignedMailValidatorMessages";
    
    private static final Class DEFAULT_CERT_PATH_REVIEWER = PKIXCertPathReviewer.class;

    private static final String EXT_KEY_USAGE = X509Extensions.ExtendedKeyUsage
            .getId();

    private static final String SUBJECT_ALTERNATIVE_NAME = X509Extensions.SubjectAlternativeName
            .getId();

    private static final int shortKeyLength = 512;
    
    // (365.25*30)*24*3600*1000
    private static final long THIRTY_YEARS_IN_MILLI_SEC = 21915l*12l*3600l*1000l;

    private CertStore certs;

    private SignerInformationStore signers;

    private Map results;

    private String[] fromAddresses;
    
    private Class certPathReviewerClass;

    /**
     * Validates the signed {@link MimeMessage} message. The
     * {@link PKIXParameters} from param are used for the certificate path
     * validation. The actual PKIXParameters used for the certificate path
     * validation is a copy of param with the followin changes: <br> - The
     * validation date is changed to the signature time <br> - A CertStore with
     * certificates and crls from the mail message is added to the CertStores.<br>
     * <br>
     * In <code>param</code> it's also possible to add additional CertStores
     * with intermediate Certificates and/or CRLs which then are also used for
     * the validation.
     * 
     * @param message
     *            the signed MimeMessage
     * @param param
     *            the parameters for the certificate path validation 
     * @throws SignedMailValidatorException
     *             if the message is no signed message or if an exception occurs
     *             reading the message
     */
    public SignedMailValidator(MimeMessage message, PKIXParameters param)
        throws SignedMailValidatorException
    {
        this(message, param, DEFAULT_CERT_PATH_REVIEWER);
    }
    
    /**
     * Validates the signed {@link MimeMessage} message. The
     * {@link PKIXParameters} from param are used for the certificate path
     * validation. The actual PKIXParameters used for the certificate path
     * validation is a copy of param with the followin changes: <br> - The
     * validation date is changed to the signature time <br> - A CertStore with
     * certificates and crls from the mail message is added to the CertStores.<br>
     * <br>
     * In <code>param</code> it's also possible to add additional CertStores
     * with intermediate Certificates and/or CRLs which then are also used for
     * the validation.
     * 
     * @param message
     *            the signed MimeMessage
     * @param param
     *            the parameters for the certificate path validation
     * @param certPathReviewerClass
     *            a subclass of {@link PKIXCertPathReviewer}. The SignedMailValidator
     *            uses objects of this type for the cert path vailidation. The class must
     *            have an empty constructor.
     * @throws SignedMailValidatorException
     *             if the message is no signed message or if an exception occurs
     *             reading the message
     * @throws IllegalArgumentException if the certPathReviewerClass is not a 
     *             subclass of {@link PKIXCertPathReviewer} or objects of 
     *             certPathReviewerClass can not be instantiated
     */
    public SignedMailValidator(MimeMessage message, PKIXParameters param, Class certPathReviewerClass)
            throws SignedMailValidatorException
    {
        this.certPathReviewerClass = certPathReviewerClass;
        try
        {
            certPathReviewerClass.asSubclass(DEFAULT_CERT_PATH_REVIEWER);
        }
        catch (ClassCastException e)
        {
            throw new IllegalArgumentException("certPathReviewerClass is not a subclass of " + DEFAULT_CERT_PATH_REVIEWER.getName());
        }
        
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
                ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                        "SignedMailValidator.noSignedMessage");
                throw new SignedMailValidatorException(msg);
            }

            // save certstore and signerInformationStore
            certs = s.getCertificatesAndCRLs("Collection", "BC");
            signers = s.getSignerInfos();

            // save "from" addresses from message
            Address[] froms = message.getFrom();
            fromAddresses = new String[froms.length];
            for (int i = 0; i < froms.length; i++)
            {
                String addr = froms[i].toString();
                int begin = addr.indexOf('<');
                if (begin != -1)
                {
                    int end = addr.indexOf('>', begin);
                    if (end != -1)
                    {
                        addr = addr.substring(begin + 1, end);
                    }
                }
                fromAddresses[i] = addr;
            }

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
            ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                    "SignedMailValidator.exceptionReadingMessage",
                    new Object[] { e.getMessage(), e , e.getClass().getName()});
            throw new SignedMailValidatorException(msg, e);
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
            List notifications = new ArrayList();

            SignerInformation signer = (SignerInformation) it.next();
            // signer certificate
            X509Certificate cert = null;

            try
            {
                Collection certCollection = findCerts(usedParameters
                        .getCertStores(), signer.getSID());

                Iterator certIt = certCollection.iterator();
                if (certIt.hasNext())
                {
                    cert = (X509Certificate) certIt.next();
                }
            }
            catch (CertStoreException cse)
            {
                ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                        "SignedMailValidator.exceptionRetrievingSignerCert",
                        new Object[] { cse.getMessage(), cse , cse.getClass().getName()});
                errors.add(msg);
            }

            if (cert != null)
            {
                // check signature
                boolean validSignature = false;
                try
                {
                    validSignature = signer.verify(cert.getPublicKey(), "BC");
                    if (!validSignature)
                    {
                        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                                "SignedMailValidator.signatureNotVerified");
                        errors.add(msg);
                    }
                }
                catch (Exception e)
                {
                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                            "SignedMailValidator.exceptionVerifyingSignature",
                            new Object[] { e.getMessage(), e, e.getClass().getName() });
                    errors.add(msg);
                }

                // check signer certificate (mail address, key usage, etc)
                checkSignerCert(cert, errors, notifications);

                // notify if a signed receip request is in the message
                AttributeTable atab = signer.getSignedAttributes();
                if (atab != null)
                {
                    Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_receiptRequest);
                    if (attr != null)
                    {
                        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                                "SignedMailValidator.signedReceiptRequest");
                        notifications.add(msg);
                    }
                }

                // check certificate path

                // get signing time if possible, otherwise use current time as
                // signing time
                Date signTime = getSignatureTime(signer);
                if (signTime == null) // no signing time was found
                {
                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                            "SignedMailValidator.noSigningTime");
                    errors.add(msg);
                    signTime = new Date();
                }
                else
                {
                    // check if certificate was valid at signing time
                    try
                    {
                        cert.checkValidity(signTime);
                    }
                    catch (CertificateExpiredException e)
                    {
                        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                                "SignedMailValidator.certExpired",
                                new Object[] { signTime, cert.getNotAfter() });
                        errors.add(msg);
                    }
                    catch (CertificateNotYetValidException e)
                    {
                        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                                "SignedMailValidator.certNotYetValid",
                                new Object[] { signTime, cert.getNotBefore() });
                        errors.add(msg);
                    }
                }
                usedParameters.setDate(signTime);

                try
                {
                    // construct cert chain
                    CertPath certPath;
                    try
                    {
                        // try to use the PKIXCertPathBuilder to create a cert
                        // path
                        CertPathBuilder builder = CertPathBuilder.getInstance(
                                "PKIX", "BC");
                        X509CertSelector select = new X509CertSelector();
                        select.setCertificate(cert);
                        PKIXBuilderParameters param = new PKIXBuilderParameters(
                                usedParameters.getTrustAnchors(), select);
                        param.setDate(usedParameters.getDate());
                        certPath = builder.build(param).getCertPath();
                    }
                    catch (Exception e)
                    {
                        // use the backup procedure to build a cert path
                        certPath = createCertPath(cert, usedParameters
                                .getTrustAnchors(), usedParameters
                                .getCertStores());
                    }

                    // validate cert chain
                    PKIXCertPathReviewer review;
                    try
                    {
                        review = (PKIXCertPathReviewer) certPathReviewerClass.newInstance();
                    }
                    catch (IllegalAccessException e)
                    {
                        throw new IllegalArgumentException("Cannot instantiate object of type " +
                                certPathReviewerClass.getName() + ": " + e.getMessage(), e);
                    }
                    catch (InstantiationException e)
                    {
                        throw new IllegalArgumentException("Cannot instantiate object of type " +
                                certPathReviewerClass.getName() + ": " + e.getMessage(), e);
                    }
                    review.init(certPath, usedParameters);
                    if (!review.isValidCertPath())
                    {
                        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                                "SignedMailValidator.certPathInvalid");
                        errors.add(msg);
                    }
                    results.put(signer, new ValidationResult(review,
                            validSignature, errors, notifications));
                }
                catch (GeneralSecurityException gse)
                {
                    // cannot create cert path
                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                            "SignedMailValidator.exceptionCreateCertPath",
                            new Object[] { gse.getMessage(), gse, gse.getClass().getName() });
                    errors.add(msg);
                    results.put(signer, new ValidationResult(null,
                            validSignature, errors, notifications));
                }
                catch (CertPathReviewerException cpre)
                {
                    // cannot initialize certpathreviewer - wrong parameters
                    errors.add(cpre.getErrorMessage());
                    results.put(signer, new ValidationResult(null,
                            validSignature, errors, notifications));
                }
            }
            else
            // no signer certificate found
            {
                ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                        "SignedMailValidator.noSignerCert");
                errors.add(msg);
                results.put(signer, new ValidationResult(null, false, errors,
                        notifications));
            }
        }
    }

    public static Set getEmailAddresses(X509Certificate cert) throws IOException, CertificateEncodingException
    {
        Set addresses = new HashSet();

        X509Principal name = PrincipalUtil.getSubjectX509Principal(cert);
        Vector oids = name.getOIDs();
        Vector names = name.getValues();
        for (int i = 0; i < oids.size(); i++)
        {
            if (oids.get(i).equals(X509Principal.EmailAddress))
            {
                String email = (String) names.get(i);
                addresses.add(email);
                break;
            }
        }

        byte[] ext = cert.getExtensionValue(SUBJECT_ALTERNATIVE_NAME);
        if (ext != null)
        {
            DERSequence altNames = (DERSequence) getObject(ext);
            for (int j = 0; j < altNames.size(); j++)
            {
                ASN1TaggedObject o = (ASN1TaggedObject) altNames
                        .getObjectAt(j);

                if (o.getTagNo() == 1)
                {
                    String email = DERIA5String.getInstance(o, true)
                            .getString().toLowerCase();
                    addresses.add(email);
                }
            }
        }

        return addresses;
    }

    private static DERObject getObject(byte[] ext) throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(ext);
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();

        aIn = new ASN1InputStream(octs.getOctets());
        return aIn.readObject();
    }

    protected void checkSignerCert(X509Certificate cert, List errors,
            List notifications)
    {
        // get key length
        PublicKey key = cert.getPublicKey();
        int keyLenght = -1;
        if (key instanceof RSAPublicKey)
        {
            keyLenght = ((RSAPublicKey) key).getModulus().bitLength();
        }
        else if (key instanceof DSAPublicKey)
        {
            keyLenght = ((DSAPublicKey) key).getParams().getP().bitLength();
        }
        if (keyLenght != -1 && keyLenght <= shortKeyLength)
        {
            ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                    "SignedMailValidator.shortSigningKey",
                    new Object[] { new Integer(keyLenght) });
            notifications.add(msg);
        }
        
        // warn if certificate has very long validity period
        long validityPeriod = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
        if (validityPeriod > THIRTY_YEARS_IN_MILLI_SEC)
        {
            ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                    "SignedMailValidator.longValidity",
                    new Object[] {cert.getNotBefore(), cert.getNotAfter()});
            notifications.add(msg);
        }

        // check key usage if digitalSignature or nonRepudiation is set
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null && !keyUsage[0] && !keyUsage[1])
        {
            ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                    "SignedMailValidator.signingNotPermitted");
            errors.add(msg);
        }

        // check extended key usage
        try
        {
            byte[] ext = cert.getExtensionValue(EXT_KEY_USAGE);
            if (ext != null)
            {
                ExtendedKeyUsage extKeyUsage = ExtendedKeyUsage
                        .getInstance(getObject(ext));
                if (!extKeyUsage
                        .hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage)
                        && !extKeyUsage
                                .hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection))
                {
                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                            "SignedMailValidator.extKeyUsageNotPermitted");
                    errors.add(msg);
                }
            }
        }
        catch (Exception e)
        {
            ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                    "SignedMailValidator.extKeyUsageError", new Object[] {
                            e.getMessage(), e, e.getClass().getName() });
            errors.add(msg);
        }

        // cert has an email address
        try
        {
            Set certEmails = getEmailAddresses(cert);
            if (certEmails.isEmpty())
            {
                // error no email address in signing certificate
                ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                        "SignedMailValidator.noEmailInCert");
                errors.add(msg);
            }
            else
            {
                // check if email in cert is equal to the from address in the
                // message
                boolean equalsFrom = false;
                for (int i = 0; i < fromAddresses.length; i++)
                {
                    if (certEmails.contains(fromAddresses[i].toLowerCase()))
                    {
                        equalsFrom = true;
                        break;
                    }
                }
                if (!equalsFrom)
                {
                    ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                            "SignedMailValidator.emailFromCertMismatch",
                            new Object[] {
                                    new UntrustedInput(Arrays
                                            .toString(fromAddresses)),
                                    new UntrustedInput(certEmails) });
                    errors.add(msg);
                }
            }
        }
        catch (Exception e)
        {
            ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                    "SignedMailValidator.certGetEmailError", new Object[] {
                            e.getMessage(), e, e.getClass().getName() });
            errors.add(msg);
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
                Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0)
                        .getDERObject());
                result = t.getDate();
            }
        }
        return result;
    }

    private List findCerts(List certStores, X509CertSelector selector)
            throws CertStoreException
    {
        List result = new ArrayList();
        Iterator it = certStores.iterator();
        while (it.hasNext())
        {
            CertStore store = (CertStore) it.next();
            Collection coll = store.getCertificates(selector);
            result.addAll(coll);
        }
        return result;
    }

    protected CertPath createCertPath(X509Certificate signerCert,
            Set trustanchors, List certStores) throws GeneralSecurityException
    {
        Set  certSet = new LinkedHashSet();

        // add signer certificate

        X509Certificate cert = signerCert;
        certSet.add(cert);

        boolean trustAnchorFound = false;
        
        X509Certificate taCert = null;

        // add other certs to the cert path
        while (cert != null && !trustAnchorFound)
        {
            // check if cert Issuer is Trustanchor
            Iterator trustIt = trustanchors.iterator();
            while (trustIt.hasNext())
            {
                TrustAnchor anchor = (TrustAnchor) trustIt.next();
                X509Certificate anchorCert = anchor.getTrustedCert();
                if (anchorCert != null)
                {
                    if (anchorCert.getSubjectX500Principal().equals(
                            cert.getIssuerX500Principal()))
                    {
                        try
                        {
                            cert.verify(anchorCert.getPublicKey(), "BC");
                            trustAnchorFound = true;
                            taCert = anchorCert;
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
                    if (anchor.getCAName().equals(
                            cert.getIssuerX500Principal().getName()))
                    {
                        try
                        {
                            cert.verify(anchor.getCAPublicKey(), "BC");
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

            if (!trustAnchorFound)
            {
                // add next cert to path
                X509CertSelector select = new X509CertSelector();
                select.setSubject(cert.getIssuerX500Principal());
                Iterator certIt = findCerts(certStores, select).iterator();

                boolean certFound = false;
                X509Certificate nextCert = null;
                while (certIt.hasNext())
                {
                    nextCert = (X509Certificate) certIt.next();
                    if (!nextCert.equals(cert))
                    {
                        certFound = true;
                        break;
                    }
                }

                if (certFound && !certSet.contains(cert))
                {
                    cert = nextCert;
                    certSet.add(cert);
                }
                else
                {
                    cert = null;
                }
            }
        }

        // if a trustanchor was found - try to find a selfsigned certificate of
        // the trustanchor
        if (trustAnchorFound)
        {
            if (taCert != null)
            {
                certSet.add(taCert);
            }
            else
            {
                X509CertSelector select = new X509CertSelector();
                select.setSubject(cert.getIssuerX500Principal());
                select.setIssuer(cert.getIssuerX500Principal());
    
                Iterator certIt = findCerts(certStores, select).iterator();
                while (certIt.hasNext())
                {
                    taCert = (X509Certificate) certIt.next();
                    try
                    {
                        cert.verify(taCert.getPublicKey(), "BC");
                        certSet.add(taCert);
                        break;
                    }
                    catch (GeneralSecurityException gse)
                    {
                        // wrong cert
                    }
                }
            }
        }
        
        CertPath certPath = CertificateFactory.getInstance("X.509", "BC").generateCertPath(new ArrayList(certSet));
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
            throws SignedMailValidatorException
    {
        if (signers.getSigners(signer.getSID()).isEmpty())
        {
            // the signer is not part of the SignerInformationStore
            // he has not signed the message
            ErrorBundle msg = new ErrorBundle(RESOURCE_NAME,
                    "SignedMailValidator.wrongSigner");
            throw new SignedMailValidatorException(msg);
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

        private List notifications;

        private boolean signVerified;

        ValidationResult(PKIXCertPathReviewer review, boolean verified,
                List errors, List notifications)
        {
            this.review = review;
            this.errors = errors;
            this.notifications = notifications;
            signVerified = verified;
        }

        /**
         * Returns a list of error messages of type {@link ErrorBundle}.
         * 
         * @return List of error messages
         */
        public List getErrors()
        {
            return errors;
        }

        /**
         * Returns a list of notification messages of type {@link ErrorBundle}.
         * 
         * @return List of notification messages
         */
        public List getNotifications()
        {
            return notifications;
        }

        /**
         * 
         * @return the PKIXCertPathReviewer for the CertPath of this signature
         *         or null if an Exception occured.
         */
        public PKIXCertPathReviewer getCertPathReview()
        {
            return review;
        }

        /**
         * 
         * @return true if the signature corresponds to the public key of the
         *         signer
         */
        public boolean isVerifiedSignature()
        {
            return signVerified;
        }

        /**
         * 
         * @return true if the signature is valid (ie. if it corresponds to the
         *         public key of the signer and the cert path for the signers
         *         certificate is also valid)
         */
        public boolean isValidSignature()
        {
            if (review != null)
            {
                return signVerified && review.isValidCertPath()
                        && errors.isEmpty();
            }
            else
            {
                return false;
            }
        }

    }
}
