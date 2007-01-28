package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.exception.ExtCertPathBuilderException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.X509CertStoreSelector;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Implements the PKIX CertPathBuilding algorithm for BouncyCastle.
 * 
 * @see CertPathBuilderSpi
 */
public class PKIXCertPathBuilderSpi extends CertPathBuilderSpi
{
    /**
     * Build and validate a CertPath using the given parameter.
     * 
     * @param params PKIXBuilderParameters object containing all information to
     *            build the CertPath
     */
    public CertPathBuilderResult engineBuild(CertPathParameters params)
            throws CertPathBuilderException, InvalidAlgorithmParameterException
    {
        if (!(params instanceof PKIXBuilderParameters)
                && !(params instanceof ExtendedPKIXBuilderParameters))
        {
            throw new InvalidAlgorithmParameterException(
                    "Parameters must be an instance of "
                            + PKIXBuilderParameters.class.getName() + " or "
                            + ExtendedPKIXBuilderParameters.class.getName()
                            + ".");
        }

        ExtendedPKIXBuilderParameters pkixParams = null;
        if (params instanceof ExtendedPKIXBuilderParameters)
        {
            pkixParams = (ExtendedPKIXBuilderParameters) params;
        }
        else
        {
            pkixParams = (ExtendedPKIXBuilderParameters) ExtendedPKIXBuilderParameters
                    .getInstance((PKIXBuilderParameters) params);
        }

        Collection targets;
        Iterator targetIter;
        List certPathList = new ArrayList();
        X509Certificate cert;

        // search target certificates

        Selector certSelect = pkixParams.getTargetConstraints();
        if (!(certSelect instanceof X509CertStoreSelector))
        {
            throw new CertPathBuilderException(
                    "TargetConstraints must be an instance of "
                            + X509CertStoreSelector.class.getName()
                            + " for "+this.getClass().getName()+" class.");
        }

        try
        {
            targets = CertPathValidatorUtilities.findCertificates(certSelect,
                    pkixParams.getStores());
        }
        catch (AnnotatedException e)
        {
            throw new ExtCertPathBuilderException("Error finding target certificate.", e);
        }

        if (targets.isEmpty())
        {
            throw new CertPathBuilderException(
                    "No certificate found matching targetContraints.");
        }

        CertPathBuilderResult result = null;

        // check all potential target certificates
        targetIter = targets.iterator();
        while (targetIter.hasNext() && result == null)
        {
            cert = (X509Certificate) targetIter.next();
            result = build(cert, pkixParams, certPathList);
        }

        if (result == null && certPathException != null)
        {
            throw new CertPathBuilderException(
                                    "Possible certificate chain could not be validated.",
                                    certPathException);
        }

        if (result == null && certPathException == null)
        {
            throw new CertPathBuilderException(
                    "Unable to find certificate chain.");
        }

        return result;
    }

    private Exception certPathException;

    private CertPathBuilderResult build(X509Certificate tbvCert,
            ExtendedPKIXBuilderParameters pkixParams, List tbvPath)

    {
        // If tbvCert is readily present in tbvPath, it indicates having run
        // into a cycle in the
        // PKI graph.
        if (tbvPath.contains(tbvCert))
        {
            return null;
        }
        // step out, the certificate is not allowed to appear in a certification
        // chain
        if (pkixParams.getExcludedCerts().contains(tbvCert))
        {
            return null;
        }
        // test if certificate path exceeds maximum length
        if (pkixParams.getMaxPathLength() != -1)
        {
            if (tbvPath.size() - 1 > pkixParams.getMaxPathLength())
            {
                return null;
            }
        }

        tbvPath.add(tbvCert);

        CertificateFactory cFact;
        CertPathValidator validator;
        CertPathBuilderResult builderResult = null;

        try
        {
            cFact = CertificateFactory.getInstance("X.509", "BC");
            validator = CertPathValidator.getInstance("PKIX", "BC");
        }
        catch (Exception e)
        {
            // cannot happen
            throw new RuntimeException(
                            "Exception creating support classes.");
        }

        try
        {
            // check wether the issuer of <tbvCert> is a TrustAnchor
            if (findTrustAnchor(tbvCert, pkixParams.getTrustAnchors()) != null)
            {
                CertPath certPath = null;
                PKIXCertPathValidatorResult result = null;
                try
                {
                    certPath = cFact.generateCertPath(tbvPath);
                }
                catch (Exception e)
                {
                    throw new AnnotatedException(
                                            "Certification path could not be constructed from certificate list.",
                                            e);
                }

                try
                {
                    result = (PKIXCertPathValidatorResult) validator.validate(
                            certPath, pkixParams);
                }
                catch (Exception e)
                {
                    throw new AnnotatedException(
                                            "Certification path could not be validated.",
                                            e);
                }

                return new PKIXCertPathBuilderResult(certPath, result
                        .getTrustAnchor(), result.getPolicyTree(), result
                        .getPublicKey());

            }
            else
            {
                // add additional X.509 stores from locations in certificate
                try
                {
                    addAdditionalStoresFromAltNames(tbvCert, pkixParams);
                }
                catch (CertificateParsingException e)
                {
                    throw new AnnotatedException(
                                            "No additiontal X.509 stores can be added from certificate locations.",
                                            e);
                }
                Collection issuers = new HashSet();
                // try to get the issuer certificate from one
                // of the stores
                try
                {
                    issuers.addAll(findIssuerCerts(tbvCert, pkixParams
                            .getStores()));
                    if (issuers.isEmpty())
                    {
                        issuers.addAll(findIssuerCerts(tbvCert, pkixParams
                                .getAddionalStores()));
                    }
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                                            "Cannot find issuer certificate for certificate in certification path.",
                                            e);
                }
                if (issuers.isEmpty())
                {
                    throw new AnnotatedException(
                            "No issuer certificate for certificate in certification path found.");
                }
                Iterator it = issuers.iterator();

                while (it.hasNext() && builderResult == null)
                {
                    X509Certificate issuer = (X509Certificate) it.next();
                    // if untrusted self signed certificate continue
                    if (issuer.getIssuerX500Principal().equals(
                            issuer.getSubjectX500Principal()))
                    {
                        continue;
                    }
                    builderResult = build(issuer, pkixParams, tbvPath);
                }
            }
        }
        catch (AnnotatedException e)
        {
            certPathException = new AnnotatedException(
                            "No valid certification path could be build.", e);
        }
        if (builderResult == null)
        {
            tbvPath.remove(tbvCert);
        }
        return builderResult;
    }

    private void addAdditionalStoresFromAltNames(X509Certificate cert,
            ExtendedPKIXParameters pkixParams)
            throws CertificateParsingException
    {
        // if in the IssuerAltName extension an URI
        // is given, add an additinal X.509 store
        if (cert.getIssuerAlternativeNames() != null)
        {
            Iterator it = cert.getIssuerAlternativeNames().iterator();
            while (it.hasNext())
            {
                // look for URI
                List list = (List) it.next();
                if (list.get(0).equals(
                        new Integer(GeneralName.uniformResourceIdentifier)))
                {
                    // found
                    String temp = (String) list.get(1);
                    CertPathValidatorUtilities.addAdditionalStoreFromLocation(
                            temp, pkixParams);
                }
            }
        }
    }

    /**
     * Search the given <code>Set</code> of TrustAnchor's for one that is the
     * issuer of the given X.509 certificate.
     * 
     * @param cert The X.509 certificate.
     * @param trustAnchors A <code>Set</code> of TrustAnchor's
     * 
     * @return The <code>TrustAnchor</code> object if found or
     *         <code>null</code> if not.
     * 
     * @exception AnnotatedException if a TrustAnchor was found but the
     *                signature verification on the given certificate has thrown
     *                an exception.
     */
    final TrustAnchor findTrustAnchor(X509Certificate cert, Set trustAnchors)
            throws AnnotatedException
    {
        Iterator iter = trustAnchors.iterator();
        TrustAnchor trust = null;
        PublicKey trustPublicKey = null;
        Exception invalidKeyEx = null;

        X509CertSelector certSelectX509 = new X509CertSelector();

        try
        {
            certSelectX509.setSubject(cert.getIssuerX500Principal()
                    .getEncoded());
        }
        catch (IOException ex)
        {
            throw new AnnotatedException(
                                    "Cannot set subject search criteria for trust anchor.",
                                    ex);
        }

        while (iter.hasNext() && trust == null)
        {
            trust = (TrustAnchor) iter.next();
            if (trust.getTrustedCert() != null)
            {
                if (certSelectX509.match(trust.getTrustedCert()))
                {
                    trustPublicKey = trust.getTrustedCert().getPublicKey();
                }
                else
                {
                    trust = null;
                }
            }
            else if (trust.getCAName() != null
                    && trust.getCAPublicKey() != null)
            {
                try
                {
                    X500Principal certIssuer = cert.getIssuerX500Principal();
                    if (certIssuer.getName().equals(trust.getCAName()))
                    {
                        trustPublicKey = trust.getCAPublicKey();
                    }
                    else
                    {
                        trust = null;
                    }
                }
                catch (IllegalArgumentException ex)
                {
                    trust = null;
                }
            }
            else
            {
                trust = null;
            }

            if (trustPublicKey != null)
            {
                try
                {
                    cert.verify(trustPublicKey);
                }
                catch (Exception ex)
                {
                    invalidKeyEx = ex;
                    trust = null;
                }
            }
        }

        if (trust == null && invalidKeyEx != null)
        {
            throw new AnnotatedException(
                                    "Trust anchor found, but certificate validation failed for certificate.",
                                    invalidKeyEx);
        }

        return trust;
    }

    /**
     * Find the issuer certificates of the given certificate.
     * 
     * @param cert The certificate for which the issuer certificate should be
     *            found.
     * @param certStores A list of <code>X509Store</code> object that will be
     *            searched through.
     * 
     * @return A <code>Collection</code> object containing the issuer
     *         <code>X509Certificate</code>s. Never <code>null</code>.
     * 
     * @exception AnnotatedException if the signature verification on the given
     *                certificate fails for all found issuer certificates or an
     *                other error occurrs.
     */
    private final Collection findIssuerCerts(X509Certificate cert,
            List certStores) throws AnnotatedException
    {
        X509CertStoreSelector certSelect = new X509CertStoreSelector();
        Set certs = new HashSet();
        try
        {
            certSelect.setSubject(cert.getIssuerX500Principal().getEncoded());
        }
        catch (IOException ex)
        {
            throw new AnnotatedException(
                                    "Subject criteria for certificate selector to find issuer certificate could not be set.",
                                    ex);
        }

        Iterator iter;

        try
        {
            iter = CertPathValidatorUtilities.findCertificates(
                    (Selector) certSelect, certStores).iterator();
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException(
                            "Issuer certificate cannot be searched.", e);
        }

        AnnotatedException lastException = null;
        boolean issuerCertFound = false;

        X509Certificate issuer = null;
        while (iter.hasNext())
        {
            issuer = (X509Certificate) iter.next();
            try
            {
                cert.verify(issuer.getPublicKey());
                certs.add(issuer);
                issuerCertFound = true;
            }
            catch (Exception ex)
            {
                lastException = new AnnotatedException(
                                        "Issued certificate could not be verified with issuer certificate.",
                                        ex);
            }
        }

        if (!issuerCertFound && lastException != null)
        {
            throw new AnnotatedException(
                                    "Issuer certificate found but certificate validation failed for certificate.",
                                    lastException);
        }

        return certs;
    }
}
