package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.TargetInformation;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.PKIXAttrCertChecker;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CRLStoreSelector;
import org.bouncycastle.x509.X509CertStoreSelector;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

class RFC3281CertPathUtilities
    extends CertPathValidatorUtilities
{
    private static final String TARGET_INFORMATION = X509Extensions.TargetInformation.getId();

    private static final String NO_REV_AVAIL = X509Extensions.NoRevAvail.getId();

    private static final String AUTHORITY_INFO_ACCESS = X509Extensions.AuthorityInfoAccess.getId();

    protected static void processAttrCert7(X509AttributeCertificate attrCert, CertPath certPath,
        CertPath holderCertPath, ExtendedPKIXParameters pkixParams) throws CertPathValidatorException
    {
        // TODO:
        // AA Controls
        // Attribute encryption
        // Proxy
        Set set = attrCert.getCriticalExtensionOIDs();
        // 7.1
        // process extensions

        // target information checked in step 6 / X509AttributeCertStoreSelector
        if (set.contains(TARGET_INFORMATION))
        {
            try
            {
                TargetInformation.getInstance(CertPathValidatorUtilities
                    .getExtensionValue(attrCert, TARGET_INFORMATION));
            }
            catch (AnnotatedException e)
            {
                throw new ExtCertPathValidatorException(
                    "Target information extension could not be read.", e);
            }
            catch (IllegalArgumentException e)
            {
                throw new ExtCertPathValidatorException(
                    "Target information extension could not be read.", e);
            }
        }
        set.remove(TARGET_INFORMATION);
        for (Iterator it = pkixParams.getAttrCertCheckers().iterator(); it.hasNext();)
        {
            ((PKIXAttrCertChecker) it.next()).check(attrCert, certPath, holderCertPath, set);
        }
        if (!set.isEmpty())
        {
            throw new CertPathValidatorException(
                "Attribute certificate contains unsupported critical extensions: "
                    + set);
        }
    }

    /**
     * Checks if an attribute certificate is revoked.
     * 
     * @param attrCert Attribute certificate to check if it is revoked.
     * @param paramsPKIX PKIX parameters.
     * @param issuerCert The issuer certificate of the attribute certificate
     *            <code>attrCert</code>.
     * @param validDate The date when the certificate revocation status should
     *            be checked.
     * 
     * @throws CertPathValidatorException if the certificate is revoked or the
     *             status cannot be checked or some error occurs.
     */
    protected static void checkCRLs(X509AttributeCertificate attrCert,
        ExtendedPKIXParameters paramsPKIX, X509Certificate issuerCert,
        Date validDate) throws CertPathValidatorException
    {
        if (paramsPKIX.isRevocationEnabled())
        {
            // check if revocation is available
            if (attrCert.getExtensionValue(NO_REV_AVAIL) == null)
            {
                CRLDistPoint crldp = null;
                try
                {
                    crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities
                        .getExtensionValue(attrCert, CRL_DISTRIBUTION_POINTS));
                }
                catch (AnnotatedException e)
                {
                    throw new CertPathValidatorException(
                        "CRL distribution point extension could not be read.", e);
                }
                try
                {
                    CertPathValidatorUtilities
                        .addAdditionalStoresFromCRLDistributionPoint(crldp, paramsPKIX);
                }
                catch (AnnotatedException e)
                {
                    throw new CertPathValidatorException(
                        "No additional CRL locations could be decoded from CRL distribution point extension.",
                        e);
                }
                CertStatus certStatus = new CertStatus();
                ReasonsMask reasonsMask = new ReasonsMask();

                AnnotatedException lastException = null;
                boolean validCrlFound = false;
                // for each distribution point
                if (crldp != null)
                {
                    DistributionPoint dps[] = null;
                    try
                    {
                        dps = crldp.getDistributionPoints();
                    }
                    catch (Exception e)
                    {
                        throw new ExtCertPathValidatorException(
                            "Distribution points could not be read.", e);
                    }
                    try
                    {
                        for (int i = 0; i < dps.length
                            && certStatus.getCertStatus() == CertStatus.UNREVOKED
                            && !reasonsMask.isAllReasons(); i++)
                        {
                            ExtendedPKIXParameters paramsPKIXClone = (ExtendedPKIXParameters) paramsPKIX
                                .clone();
                            checkCRL(dps[i], attrCert, paramsPKIXClone,
                                validDate, issuerCert, certStatus, reasonsMask);
                            validCrlFound = true;
                        }
                    }
                    catch (AnnotatedException e)
                    {
                        lastException = new AnnotatedException(
                            "No valid CRL for distribution point found.", e);
                    }
                }

                /*
                 * If the revocation status has not been determined, repeat the
                 * process above with any available CRLs not specified in a
                 * distribution point but issued by the certificate issuer.
                 */

                if (certStatus.getCertStatus() == CertStatus.UNREVOKED
                    && !reasonsMask.isAllReasons())
                {
                    try
                    {
                        /*
                         * assume a DP with both the reasons and the cRLIssuer
                         * fields omitted and a distribution point name of the
                         * certificate issuer.
                         */
                        DERObject issuer = null;
                        try
                        {

                            issuer = new ASN1InputStream(
                                ((X500Principal) attrCert.getIssuer()
                                    .getPrincipals()[0]).getEncoded())
                                .readObject();
                        }
                        catch (Exception e)
                        {
                            throw new AnnotatedException(
                                "Issuer from certificate for CRL could not be reencoded.",
                                e);
                        }
                        DistributionPoint dp = new DistributionPoint(
                            new DistributionPointName(0, new GeneralNames(
                                new GeneralName(GeneralName.directoryName,
                                    issuer))), null, null);
                        ExtendedPKIXParameters paramsPKIXClone = (ExtendedPKIXParameters) paramsPKIX
                            .clone();
                        checkCRL(dp, attrCert, paramsPKIXClone, validDate,
                            issuerCert, certStatus, reasonsMask);
                        validCrlFound = true;
                    }
                    catch (AnnotatedException e)
                    {
                        lastException = new AnnotatedException(
                            "No valid CRL for distribution point found.", e);
                    }
                }

                if (!validCrlFound)
                {
                    throw new ExtCertPathValidatorException(
                        "No valid CRL found.", lastException);
                }
                if (certStatus.getCertStatus() != CertStatus.UNREVOKED)
                {
                    String message = "Attribute certificate revocation after "
                        + certStatus.getRevocationDate();
                    message += ", reason: "
                        + crlReasons[certStatus.getCertStatus()];
                    throw new CertPathValidatorException(message);
                }
                if (!reasonsMask.isAllReasons()
                    && certStatus.getCertStatus() == CertStatus.UNREVOKED)
                {
                    certStatus.setCertStatus(CertStatus.UNDETERMINED);
                }
                if (certStatus.getCertStatus() == CertStatus.UNDETERMINED)
                {
                    throw new CertPathValidatorException(
                        "Attribute certificate status could not be determined.");
                }

            }
            else
            {
                if (attrCert.getExtensionValue(CRL_DISTRIBUTION_POINTS) != null
                    || attrCert.getExtensionValue(AUTHORITY_INFO_ACCESS) != null)
                {
                    throw new CertPathValidatorException(
                        "No rev avail extension is set, but also an AC revocation pointer.");
                }
            }
        }
    }

    protected static void additionalChecks(X509AttributeCertificate attrCert,
        ExtendedPKIXParameters pkixParams) throws CertPathValidatorException
    {
        // 1
        for (Iterator it = pkixParams.getProhibitedACAttributes().iterator(); it
            .hasNext();)
        {
            String oid = (String) it.next();
            if (attrCert.getAttributes(oid) != null)
            {
                throw new CertPathValidatorException(
                    "Attribute certificate contains prohibited attribute: "
                        + oid + ".");
            }
        }
        for (Iterator it = pkixParams.getNecessaryACAttributes().iterator(); it
            .hasNext();)
        {
            String oid = (String) it.next();
            if (attrCert.getAttributes(oid) == null)
            {
                throw new CertPathValidatorException(
                    "Attribute certificate does not contain necessary attribute: "
                        + oid + ".");
            }
        }
    }

    protected static void processAttrCert5(X509AttributeCertificate attrCert,
        ExtendedPKIXParameters pkixParams) throws CertPathValidatorException
    {
        try
        {
            attrCert.checkValidity(CertPathValidatorUtilities
                .getValidDate(pkixParams));
        }
        catch (CertificateExpiredException e)
        {
            throw new ExtCertPathValidatorException(
                "Attribute certificate is not valid.", e);
        }
        catch (CertificateNotYetValidException e)
        {
            throw new ExtCertPathValidatorException(
                "Attribute certificate is not valid.", e);
        }
    }

    protected static void processAttrCert4(X509Certificate acIssuerCert,
        ExtendedPKIXParameters pkixParams) throws CertPathValidatorException
    {
        Set set = pkixParams.getTrustedACIssuers();
        boolean trusted = false;
        for (Iterator it = set.iterator(); it.hasNext();)
        {
            TrustAnchor anchor = (TrustAnchor) it.next();
            if (acIssuerCert.getSubjectX500Principal().getName("RFC2253")
                .equals(anchor.getCAName())
                || acIssuerCert.equals(anchor.getTrustedCert()))
            {
                trusted = true;
            }
        }
        if (!trusted)
        {
            throw new CertPathValidatorException(
                "Attribute certificate issuer is not directly trusted.");
        }
    }

    protected static void processAttrCert3(X509Certificate acIssuerCert,
        ExtendedPKIXParameters pkixParams) throws CertPathValidatorException
    {
        if (acIssuerCert.getKeyUsage() != null
            && (!acIssuerCert.getKeyUsage()[0] && !acIssuerCert.getKeyUsage()[1]))
        {
            throw new CertPathValidatorException(
                "Attribute certificate issuer public key cannot be used to validate digital signatures.");
        }
        if (acIssuerCert.getBasicConstraints() != -1)
        {
            throw new CertPathValidatorException(
                "Attribute certificate issuer is also a public key certificate issuer.");
        }
    }

    protected static CertPathValidatorResult processAttrCert2(
        CertPath certPath, ExtendedPKIXParameters pkixParams)
        throws CertPathValidatorException
    {
        CertPathValidator validator = null;
        try
        {
            validator = CertPathValidator.getInstance("PKIX", "BC");
        }
        catch (NoSuchProviderException e)
        {
            throw new ExtCertPathValidatorException(
                "Support class could not be created.", e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new ExtCertPathValidatorException(
                "Support class could not be created.", e);
        }
        try
        {
            return validator.validate(certPath, pkixParams);
        }
        catch (CertPathValidatorException e)
        {
            throw new ExtCertPathValidatorException(
                "Certification path for issuer certificate of attribute certificate could not be validated.",
                e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // must be a programming error
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * Searches for a holder public key certificate and verifies its
     * certification path.
     * 
     * @param attrCert the attribute certificate.
     * @param pkixParams The PKIX parameters.
     * @return The certificate path of the holder certificate.
     * @throws AnnotatedException if
     *             <ul>
     *             <li>no public key certificate can be found although holder
     *             information is given by an entity name or a base certificate
     *             ID
     *             <li>support classes cannot be created
     *             <li>no certification path for the public key certificate can
     *             be built
     *             </ul>
     */
    protected static CertPath processAttrCert1(X509AttributeCertificate attrCert,
        ExtendedPKIXParameters pkixParams) throws CertPathValidatorException
    {
        CertPathBuilderResult result = null;
        // find holder PKCs
        Set holderPKCs = new HashSet();
        if (attrCert.getHolder().getIssuer() != null)
        {
            X509CertStoreSelector selector = new X509CertStoreSelector();
            selector.setSerialNumber(attrCert.getHolder().getSerialNumber());
            Principal[] principals = attrCert.getHolder().getIssuer();
            for (int i = 0; i < principals.length; i++)
            {
                try
                {
                    if (principals[i] instanceof X500Principal)
                    {
                        selector.setIssuer(((X500Principal)principals[i]).getEncoded());
                    }
                    holderPKCs.addAll(CertPathValidatorUtilities
                        .findCertificates((Selector) selector, pkixParams
                            .getStores()));
                }
                catch (AnnotatedException e)
                {
                    throw new ExtCertPathValidatorException(
                        "Public key certificate for attribute certificate cannot be searched.",
                        e);
                }
                catch (IOException e)
                {
                    throw new ExtCertPathValidatorException(
                        "Unable to encode X500 principal.",
                        e);
                }
            }
            if (holderPKCs.isEmpty())
            {
                throw new CertPathValidatorException(
                    "Public key certificate specified in base certificate ID for attribute certificate cannot be found.");
            }
        }
        if (attrCert.getHolder().getEntityNames() != null)
        {
            X509CertStoreSelector selector = new X509CertStoreSelector();
            Principal[] principals = attrCert.getHolder().getEntityNames();
            for (int i = 0; i < principals.length; i++)
            {
                try
                {
                    if (principals[i] instanceof X500Principal)
                    {
                        selector.setIssuer(((X500Principal)principals[i]).getEncoded());
                    }
                    holderPKCs.addAll(CertPathValidatorUtilities
                        .findCertificates((Selector) selector, pkixParams
                            .getStores()));
                }
                catch (AnnotatedException e)
                {
                    throw new ExtCertPathValidatorException(
                        "Public key certificate for attribute certificate cannot be searched.",
                        e);
                }
                catch (IOException e)
                {
                    throw new ExtCertPathValidatorException(
                        "Unable to encode X500 principal.",
                        e);
                }
            }
            if (holderPKCs.isEmpty())
            {
                throw new CertPathValidatorException(
                    "Public key certificate specified in entity name for attribute certificate cannot be found.");
            }
        }
        // verify cert paths for PKCs
        ExtendedPKIXBuilderParameters params = (ExtendedPKIXBuilderParameters) ExtendedPKIXBuilderParameters
            .getInstance(pkixParams);
        CertPathValidatorException lastException = null;
        for (Iterator it = holderPKCs.iterator(); it.hasNext();)
        {
            X509CertStoreSelector selector = new X509CertStoreSelector();
            selector.setCertificate((X509Certificate) it.next());
            params.setTargetConstraints(selector);
            CertPathBuilder builder = null;
            try
            {
                builder = CertPathBuilder.getInstance("PKIX", "BC");
            }
            catch (NoSuchProviderException e)
            {
                throw new ExtCertPathValidatorException(
                    "Support class could not be created.", e);
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new ExtCertPathValidatorException(
                    "Support class could not be created.", e);
            }
            try
            {
                result = builder
                    .build(ExtendedPKIXBuilderParameters.getInstance(params));
            }
            catch (CertPathBuilderException e)
            {
                lastException = new ExtCertPathValidatorException(
                    "Certification path for public key certificate of attribute certificate could not be build.",
                    e);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                // must be a programming error
                throw new RuntimeException(e.getMessage());
            }
        }
        if (lastException != null)
        {
            throw lastException;
        }
        return result.getCertPath();
    }

    /**
     * 
     * Checks a distribution point for revocation information for the
     * certificate <code>cert</code>.
     * 
     * @param dp The distribution point to consider.
     * @param attrCert The attribute certificate which should be checked.
     * @param paramsPKIX PKIX parameters.
     * @param validDate The date when the certificate revocation status should
     *            be checked.
     * @param issuerCert Certificate to check if it is revoked.
     * @param reasonMask The reasons mask which is already checked.
     * @throws AnnotatedException if the certificate is revoked or the status
     *             cannot be checked or some error occurs.
     */
    private static void checkCRL(DistributionPoint dp,
        X509AttributeCertificate attrCert, ExtendedPKIXParameters paramsPKIX,
        Date validDate, X509Certificate issuerCert, CertStatus certStatus,
        ReasonsMask reasonMask) throws AnnotatedException
    {

        /*
         * 4.3.6 No Revocation Available
         * 
         * The noRevAvail extension, defined in [X.509-2000], allows an AC
         * issuer to indicate that no revocation information will be made
         * available for this AC.
         */
        if (attrCert.getExtensionValue(X509Extensions.NoRevAvail.getId()) != null)
        {
            return;
        }
        Date currentDate = new Date(System.currentTimeMillis());
        if (validDate.getTime() > currentDate.getTime())
        {
            throw new AnnotatedException("Validation time is in future.");
        }

        // (a)
        /*
         * We always get timely valid CRLs, so there is no step (a) (1).
         * "locally cached" CRLs are assumed to be in getStore(), additional
         * CRLs must be enabled in the ExtendedPKIXParameters and are in
         * getAdditionalStore()
         */

        Set crls = CertPathValidatorUtilities.getCompleteCRLs(dp, attrCert,
            currentDate, paramsPKIX);
        boolean validCrlFound = false;
        AnnotatedException lastException = null;
        Iterator crl_iter = crls.iterator();

        while (crl_iter.hasNext()
            && certStatus.getCertStatus() == CertStatus.UNREVOKED
            && !reasonMask.isAllReasons())
        {
            try
            {
                X509CRL crl = (X509CRL) crl_iter.next();

                // (d)
                ReasonsMask interimReasonsMask = processCRLD(crl, dp);

                // (e)
                /*
                 * The reasons mask is updated at the end, so only valid CRLs
                 * can update it. If this CRL does not contain new reasons it
                 * must be ignored.
                 */
                if (!interimReasonsMask.hasNewReasons(reasonMask))
                {
                    continue;
                }

                // (f)
                Set keys = processCRLF(crl, attrCert,
                    null, null, paramsPKIX);
                // (g)
                PublicKey key = processCRLG(crl, keys);

                X509CRL deltaCRL = null;

                if (paramsPKIX.isUseDeltasEnabled())
                {
                    // get delta CRLs
                    Set deltaCRLs = CertPathValidatorUtilities.getDeltaCRLs(
                        currentDate, paramsPKIX, crl);
                    // we only want one valid delta CRL
                    // (h)
                    deltaCRL = processCRLH(deltaCRLs,
                        key);
                }

                /*
                 * CRL must be be valid at the current time, not the validation
                 * time. If a certificate is revoked with reason keyCompromise,
                 * cACompromise, it can be used for forgery, also for the past.
                 * This reason may not be contained in older CRLs.
                 */

                /*
                 * in the chain model signatures stay valid also after the
                 * certificate has been expired, so they do not have to be in
                 * the CRL vality time
                 */

                if (paramsPKIX.getValidityModel() != ExtendedPKIXParameters.CHAIN_VALIDITY_MODEL)
                {
                    /*
                     * if a certificate has expired, but was revoked, it is not
                     * more in the CRL, so it would be regarded as valid if the
                     * first check is not done
                     */
                    if (attrCert.getNotAfter().getTime() < crl.getThisUpdate()
                        .getTime())
                    {
                        throw new AnnotatedException(
                            "No valid CRL for current time found.");
                    }
                }

                processCRLB1(dp, attrCert, crl);

                // (b) (2)
                processCRLB2(dp, attrCert, crl);

                // (c)
                processCRLC(deltaCRL, crl, paramsPKIX);

                // (i)
                processCRLI(validDate, deltaCRL,
                    attrCert.getSerialNumber(), certStatus, paramsPKIX);

                // (j)
                processCRLJ(validDate, crl, attrCert
                    .getSerialNumber(), certStatus);

                // (k)
                if (certStatus.getCertStatus() == CRLReason.removeFromCRL)
                {
                    certStatus.setCertStatus(CertStatus.UNREVOKED);
                }

                // update reasons mask
                reasonMask.addReasons(interimReasonsMask);
                validCrlFound = true;
            }
            catch (AnnotatedException e)
            {
                lastException = e;
            }
        }
        if (!validCrlFound)
        {
            throw lastException;
        }
    }

    protected static void processCRLB2(DistributionPoint dp,
            Object cert, X509CRL crl) throws AnnotatedException
        {
            IssuingDistributionPoint idp = null;
            try
            {
                idp = IssuingDistributionPoint
                    .getInstance(CertPathValidatorUtilities.getExtensionValue(crl,
                        ISSUING_DISTRIBUTION_POINT));
            }
            catch (Exception e)
            {
                throw new AnnotatedException(
                    "Issuing distribution point extension could not be decoded.", e);
            }
            // distribution point name is present
            if (idp != null && idp.getDistributionPoint() != null)
            {
                // make list of names
                DistributionPointName dpName = IssuingDistributionPoint
                    .getInstance(idp).getDistributionPoint();
                List names = new ArrayList();
                if (dpName.getType() == DistributionPointName.FULL_NAME)
                {
                    GeneralName[] genNames = GeneralNames.getInstance(
                        dpName.getName()).getNames();
                    for (int j = 0; j < genNames.length; j++)
                    {
                        names.add(genNames[j].getDEREncoded());
                    }
                }
                boolean matches = false;
                // verify that one of the names in the IDP matches one
                // of the names in the DP.
                if (dp.getDistributionPoint() != null)
                {
                    dpName = dp.getDistributionPoint();
                    if (dpName.getType() == DistributionPointName.FULL_NAME)
                    {
                        GeneralName[] genNames = GeneralNames.getInstance(
                            dpName.getName()).getNames();
                        for (int j = 0; j < genNames.length; j++)
                        {
                            if (names.contains(genNames[j]))
                            {
                                matches = true;
                                break;
                            }
                        }
                    }
                    if (!matches)
                    {
                        throw new AnnotatedException(
                            "None of the names in the CRL issuing distribution point matches one "
                                + "of the names in a distributionPoint field of the certificate CRL distribution point.");
                    }
                }
                // verify that one of the names in
                // the IDP matches one of the names in the cRLIssuer field of
                // the DP
                else
                {
                    if (dp.getCRLIssuer() == null)
                    {
                        throw new AnnotatedException(
                            "Either the cRLIssuer or the distributionPoint field must "
                                + "be contained in DistributionPoint.");
                    }
                    GeneralName[] genNames = dp.getCRLIssuer().getNames();
                    for (int j = 0; j < genNames.length; j++)
                    {
                        if (names.contains(genNames[j]))
                        {
                            matches = true;
                            break;
                        }
                    }
                    if (!matches)
                    {
                        throw new AnnotatedException(
                            "None of the names in the CRL issuing distribution point matches one "
                                + "of the names in a cRLIssuer field of the certificate CRL distribution point.");
                    }
                }
                BasicConstraints bc = null;
                try
                {
                    bc = BasicConstraints.getInstance(CertPathValidatorUtilities
                        .getExtensionValue((java.security.cert.X509Extension)cert, BASIC_CONSTRAINTS));
                }
                catch (Exception e)
                {
                    throw new AnnotatedException(
                                "Basic constraints extension could not be decoded.",
                                e);
                }

                if (cert instanceof X509Certificate)
                {
                    // (b) (ii)
                    if (idp.onlyContainsUserCerts() && (bc != null && bc.isCA()))
                    {
                        throw new AnnotatedException(
                            "CA Cert CRL only contains user certificates.");
                    }

                    // (b) (iii)
                    if (idp.onlyContainsCACerts() && (bc == null || !bc.isCA()))
                    {
                        throw new AnnotatedException(
                            "End CRL only contains CA certificates.");
                    }
                }

                // (b) (iv)
                if (idp.onlyContainsAttributeCerts())
                {
                    throw new AnnotatedException(
                        "onlyContainsAttributeCerts boolean is asserted.");
                }
            }
        }

        protected static void processCRLB1(DistributionPoint dp, Object cert,
            X509CRL crl) throws AnnotatedException
        {
            DERObject idp = CertPathValidatorUtilities.getExtensionValue(crl,
                ISSUING_DISTRIBUTION_POINT);
            boolean isIndirect = false;
            if (idp != null)
            {
                if (IssuingDistributionPoint.getInstance(idp).isIndirectCRL())
                {
                    isIndirect = true;
                }
            }
            byte[] issuerBytes = CertPathValidatorUtilities.getIssuerPrincipal(crl)
                .getEncoded();

            boolean matchIssuer = false;
            if (dp.getCRLIssuer() != null)
            {
                GeneralName genNames[] = dp.getCRLIssuer().getNames();
                for (int j = 0; j < genNames.length; j++)
                {
                    if (genNames[j].getTagNo() == GeneralName.directoryName)
                    {
                        try
                        {
                            if (genNames[j].getName().getDERObject().getEncoded()
                                .equals(issuerBytes))
                            {
                                matchIssuer = true;
                            }
                        }
                        catch (IOException e)
                        {
                            throw new AnnotatedException(
                                        "CRL issuer information from distribution point cannot be decoded.",
                                        e);
                        }
                    }
                }
                if (matchIssuer && !isIndirect)
                {
                    throw new AnnotatedException(
                        "Distribution point contains cRLIssuer field but CRL is not indirect.");
                }
                if (!matchIssuer)
                {
                    throw new AnnotatedException(
                        "CRL issuer of CRL does not match CRL issuer of distribution point.");
                }
            }
            else
            {
                if (CertPathValidatorUtilities.getIssuerPrincipal(crl).equals(
                    CertPathValidatorUtilities.getEncodedIssuerPrincipal(cert)))
                {
                    matchIssuer = true;
                }
            }
            if (!matchIssuer)
            {
                throw new AnnotatedException(
                    "Cannot find matching CRL issuer for certificate.");
            }
        }

        protected static ReasonsMask processCRLD(X509CRL crl, DistributionPoint dp)
            throws AnnotatedException
        {
            IssuingDistributionPoint idp = null;
            try
            {
                idp = IssuingDistributionPoint
                    .getInstance(CertPathValidatorUtilities.getExtensionValue(crl,
                        ISSUING_DISTRIBUTION_POINT));
            }
            catch (Exception e)
            {
                throw new AnnotatedException(
                    "Issuing distribution point extension could not be decoded.", e);
            }
            // (d) (1)
            if (idp != null && idp.getOnlySomeReasons() != null
                && dp.getReasons() != null)
            {
                return new ReasonsMask(dp.getReasons().intValue())
                    .intersect(new ReasonsMask(idp.getOnlySomeReasons().intValue()));
            }
            // (d) (4)
            if ((idp == null || idp.getOnlySomeReasons() == null)
                && dp.getReasons() == null)
            {
                return ReasonsMask.allReasons;
            }
            // (d) (2) and (d)(3)
            return (dp.getReasons() == null ? ReasonsMask.allReasons
                : new ReasonsMask(dp.getReasons().intValue()))
                .intersect(idp == null ? ReasonsMask.allReasons : new ReasonsMask(
                    idp.getOnlySomeReasons().intValue()));

        }

        /**
         * Obtain and validate the certification path for the complete CRL issuer.
         * If a key usage extension is present in the CRL issuer's certificate,
         * verify that the cRLSign bit is set.
         *
         * @param crl CRL which contains revocation information for the certificate
         *            <code>cert</code>.
         * @param cert The attribute certificate or certificate to check if it is
         *            revoked.
         * @param defaultCRLSignCert The issuer certificate of the certificate
         *            <code>cert</code>. May be <code>null</code>.
         * @param defaultCRLSignKey The public key of the issuer certificate
         *            <code>defaultCRLSignCert</code>. May be <code>null</code>.
         * @param paramsPKIX paramsPKIX PKIX parameters.
         * @return A <code>Set</code> with all keys of possible CRL issuer
         *         certificates.
         * @throws AnnotatedException if the CRL is no valid or the status cannot be
         *             checked or some error occurs.
         */
        protected static Set processCRLF(X509CRL crl, Object cert,
            X509Certificate defaultCRLSignCert, PublicKey defaultCRLSignKey,
            ExtendedPKIXParameters paramsPKIX) throws AnnotatedException
        {
            // (f)

            // get issuer from CRL
            X509CertStoreSelector selector = new X509CertStoreSelector();
            try
            {
                selector.setSubject(CertPathValidatorUtilities.getIssuerPrincipal(
                    crl).getEncoded());
            }
            catch (IOException e)
            {
                throw new AnnotatedException(
                    "Subject criteria for certificate selector to find issuer certificate for CRL could not be set.",
                    e);
            }

            // get CRL signing certs
            Collection coll = null;
            try
            {
                coll = CertPathValidatorUtilities.findCertificates(
                    (Selector) selector, paramsPKIX.getStores());
                coll = CertPathValidatorUtilities.findCertificates(
                    (Selector) selector, paramsPKIX.getAddionalStores());
            }
            catch (AnnotatedException e)
            {
                throw new AnnotatedException(
                    "Issuer certificate for CRL cannot be searched.", e);
            }

            if (defaultCRLSignCert != null)
            {
                coll.add(defaultCRLSignCert);
            }
            Iterator cert_it = coll.iterator();

            Set validCerts = new HashSet();

            while (cert_it.hasNext())
            {
                X509Certificate signingCert = (X509Certificate) cert_it.next();

                /*
                 * CA of certificate, for which this CRL is checked, also signed
                 * CRL, so skip path validation, because is already checked in way
                 * from trusted CA to end certificate.
                 */
                // double check with key, because name could be thereotical the same
                if (CertPathValidatorUtilities.getEncodedIssuerPrincipal(cert)
                    .equals(signingCert.getSubjectX500Principal())
                    && signingCert.getPublicKey().equals(defaultCRLSignKey))
                {
                    validCerts.add(signingCert);
                    continue;
                }
                try
                {
                    CertPathBuilder builder = CertPathBuilder.getInstance("PKIX",
                        "BC");
                    selector = new X509CertStoreSelector();
                    selector.setCertificate(signingCert);
                    ExtendedPKIXBuilderParameters params = (ExtendedPKIXBuilderParameters) ExtendedPKIXBuilderParameters
                        .getInstance(paramsPKIX);
                    params.setTargetConstraints(selector);
                    /*
                     * CRL for CA cannot be signed from CA lower in PKI path
                     * (compromised key of upper CA could be used to forge this CA.)
                     * (and we run in an endless loop aside from this.)
                     */
                    // cert is not allowed to appear in PKI path
                    Set excluded = new HashSet();
                    excluded.add(cert);
                    params.setExcludedCerts(excluded);
                    builder.build(params);
                    validCerts.add(signingCert);
                }
                catch (Exception e)
                {
                }
            }

            Set checkKeys = new HashSet();

            // trivially included if cert cannot be checked for key usage extension
            if (defaultCRLSignCert == null && defaultCRLSignKey != null)
            {
                checkKeys.add(defaultCRLSignKey);
            }

            AnnotatedException lastException = null;
            for (Iterator it = validCerts.iterator(); it.hasNext();)
            {
                X509Certificate signCert = (X509Certificate) it.next();
                boolean[] keyusage = signCert.getKeyUsage();

                if (keyusage != null
                    && (keyusage.length < 7 || !keyusage[CRL_SIGN]))
                {
                    lastException = new AnnotatedException(
                        "Issuer certificate key usage extension does not permit CRL signing.");
                }
                else
                {
                    checkKeys.add(signCert.getPublicKey());
                }
            }

            if (checkKeys.isEmpty() && lastException == null)
            {
                throw new AnnotatedException(
                    "Cannot find a valid issuer certificate.");
            }
            if (checkKeys.isEmpty() && lastException != null)
            {
                throw lastException;
            }

            return checkKeys;
        }

        protected static PublicKey processCRLG(X509CRL crl, Set keys)
            throws AnnotatedException
        {
            Exception lastException = null;
            try
            {
                for (Iterator it = keys.iterator(); it.hasNext();)
                {
                    PublicKey key = (PublicKey) it.next();
                    crl.verify(key);
                    return key;
                }
            }
            catch (Exception e)
            {
                lastException = e;
            }
            throw new AnnotatedException("Cannot verify CRL.", lastException);
        }

        protected static X509CRL processCRLH(Set deltacrls, PublicKey key)
            throws AnnotatedException
        {
            Exception lastException = null;
            try
            {
                for (Iterator it = deltacrls.iterator(); it.hasNext();)
                {
                    X509CRL crl = (X509CRL) it.next();
                    crl.verify(key);
                    return crl;
                }
            }
            catch (Exception e)
            {
                lastException = e;
            }
            throw new AnnotatedException("Cannot verify delta CRL.", lastException);
        }

        protected static Set processCRLA1i(Date currentDate,
            ExtendedPKIXParameters paramsPKIX, X509Certificate cert, X509CRL crl)
            throws AnnotatedException
        {
            Set set = new HashSet();
            if (paramsPKIX.isUseDeltasEnabled())
            {
                CRLDistPoint freshestCRL = null;
                try
                {
                    freshestCRL = CRLDistPoint
                        .getInstance(CertPathValidatorUtilities.getExtensionValue(
                            cert, FRESHEST_CRL));
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                                "Freshest CRL extension could not be decoded from certificate.",
                                e);
                }
                if (freshestCRL == null)
                {
                    try
                    {
                        freshestCRL = CRLDistPoint
                            .getInstance(CertPathValidatorUtilities
                                .getExtensionValue(crl, FRESHEST_CRL));
                    }
                    catch (AnnotatedException e)
                    {
                        throw new AnnotatedException(
                                    "Freshest CRL extension could not be decoded from CRL.",
                                    e);
                    }
                }
                if (freshestCRL != null)
                {
                    try
                    {
                        CertPathValidatorUtilities
                            .addAdditionalStoresFromCRLDistributionPoint(
                                freshestCRL, paramsPKIX);
                    }
                    catch (AnnotatedException e)
                    {
                        throw new AnnotatedException(
                                    "No new delta CRL locations could be added from Freshest CRL extension.",
                                    e);
                    }
                    // get delta CRL(s)
                    try
                    {
                        set.addAll(CertPathValidatorUtilities.getDeltaCRLs(
                            currentDate, paramsPKIX, crl));
                    }
                    catch (AnnotatedException e)
                    {
                        throw new AnnotatedException(
                                "Exception obtaining delta CRLs.", e);
                    }
                }
            }
            return set;
        }

        protected static Set[] processCRLA1ii(Date currentDate,
            ExtendedPKIXParameters paramsPKIX, X509Certificate cert, X509CRL crl)
            throws AnnotatedException
        {
            Set completeSet = new HashSet();
            Set deltaSet = new HashSet();
            X509CRLStoreSelector crlselect = new X509CRLStoreSelector();
            crlselect.setCertificateChecking(cert);
            crlselect.setCompleteCRLEnabled(true);
            crlselect.setDateAndTime(currentDate);
            try
            {
                crlselect.addIssuerName(crl.getIssuerX500Principal().getEncoded());
            }
            catch (IOException e)
            {
                throw new AnnotatedException(
                        "Cannot extract issuer from CRL." + e, e);
            }
            // get complete CRL(s)
            try
            {
                completeSet.addAll(CertPathValidatorUtilities.findCRLs(crlselect,
                    paramsPKIX.getAddionalStores()));
                completeSet.addAll(CertPathValidatorUtilities.findCRLs(crlselect,
                    paramsPKIX.getStores()));
            }
            catch (AnnotatedException e)
            {
                throw new AnnotatedException(
                        "Exception obtaining complete CRLs.", e);
            }
            if (paramsPKIX.isUseDeltasEnabled())
            {
                // get delta CRL(s)
                try
                {
                    deltaSet.addAll(CertPathValidatorUtilities.getDeltaCRLs(
                        currentDate, paramsPKIX, crl));
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                            "Exception obtaining delta CRLs.", e);
                }
            }
            return new Set[]
            { completeSet, deltaSet };
        }

        /**
         * If use-deltas is set, verify the issuer and scope of the delta CRL.
         *
         * @param deltaCRL The delta CRL.
         * @param completeCRL The complete CRL.
         * @param pkixParams The PKIX paramaters.
         * @throws AnnotatedException if an exception occurs.
         */
        protected static void processCRLC(X509CRL deltaCRL, X509CRL completeCRL,
            ExtendedPKIXParameters pkixParams) throws AnnotatedException
        {
            IssuingDistributionPoint completeidp = null;
            try
            {
                completeidp = IssuingDistributionPoint
                    .getInstance(CertPathValidatorUtilities.getExtensionValue(
                        completeCRL,
                        ISSUING_DISTRIBUTION_POINT));
            }
            catch (Exception e)
            {
                throw new AnnotatedException(
                    "Issuing distribution point extension could not be decoded.", e);
            }

            if (pkixParams.isUseDeltasEnabled())
            {

                // (c) (1)
                if (!deltaCRL.getIssuerX500Principal().equals(
                    completeCRL.getIssuerX500Principal()))
                {
                    throw new AnnotatedException(
                        "Complete CRL issuer does not match delta CRL issuer.");
                }

                // (c) (2)
                if (completeidp != null)
                {

                    IssuingDistributionPoint deltaidp = null;
                    try
                    {
                        deltaidp = IssuingDistributionPoint
                            .getInstance(CertPathValidatorUtilities
                                .getExtensionValue(deltaCRL,
                                    ISSUING_DISTRIBUTION_POINT));
                    }
                    catch (Exception e)
                    {
                        throw new AnnotatedException(
                                    "Issuing distribution point extension from delta CRL could not be decoded.",
                                    e);
                    }
                    boolean match = false;
                    if (completeidp == null)
                    {
                        if (deltaidp == null)
                        {
                            match = true;
                        }
                    }
                    else
                    {
                        if (completeidp.equals(deltaidp))
                        {
                            match = true;
                        }
                    }
                    if (!match)
                    {
                        throw new AnnotatedException(
                            "Issuing distribution point extension from delta CRL and complete CRL does not match.");
                    }
                }

                // (c) (3)
                DERObject completeKeyIdentifier = null;
                try
                {
                    completeKeyIdentifier = CertPathValidatorUtilities
                        .getExtensionValue(deltaCRL, AUTHORITY_KEY_IDENTIFIER);
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                                "Authority key identifier extension could not be extracted from complete CRL.",
                                e);
                }
                DERObject deltaKeyIdentifier = null;
                try
                {
                    deltaKeyIdentifier = CertPathValidatorUtilities
                        .getExtensionValue(deltaCRL, AUTHORITY_KEY_IDENTIFIER);
                }
                catch (AnnotatedException e)
                {
                    throw new AnnotatedException(
                                "Authority key identifier extension could not be extracted from delta CRL.",
                                e);
                }
                if (!completeKeyIdentifier.equals(deltaKeyIdentifier))
                {
                    throw new AnnotatedException(
                        "Delta CRL authority key identifier does not match complete CRL authority key identifier.");
                }
            }
        }

        protected static void processCRLI(Date validDate, X509CRL deltacrl,
            BigInteger serialNumber, CertStatus certStatus,
            ExtendedPKIXParameters pkixParams) throws AnnotatedException
        {
            if (pkixParams.isUseDeltasEnabled())
            {
                CertPathValidatorUtilities.getCertStatus(validDate, deltacrl, serialNumber, certStatus);
            }
        }

        protected static void processCRLJ(Date validDate, X509CRL completecrl,
            BigInteger serialNumber, CertStatus certStatus) throws AnnotatedException
        {
            CertPathValidatorUtilities.getCertStatus(validDate, completecrl, serialNumber, certStatus);
        }

        /**
         *
         * Checks a distribution point for revocation information for the
         * certificate <code>cert</code>.
         *
         * @param dp The distribution point to consider.
         * @param paramsPKIX PKIX parameters.
         * @param cert Certificate to check if it is revoked.
         * @param validDate The date when the certificate revocation status should
         *            be checked.
         * @param defaultCRLSignCert The issuer certificate of the certificate
         *            <code>cert</code>.
         * @param defaultCRLSignKey The public key of the issuer certificate
         *            <code>defaultCRLSignCert</code>.
         * @param certStatus The current certificate revocation status.
         * @param reasonMask The reasons mask which is already checked.
         * @param certPathCerts The certificates of the certification path.
         * @throws AnnotatedException if the certificate is revoked or the status
         *             cannot be checked or some error occurs.
         */
        private static void checkCRL(DistributionPoint dp,
            ExtendedPKIXParameters paramsPKIX, X509Certificate cert,
            Date validDate, X509Certificate defaultCRLSignCert,
            PublicKey defaultCRLSignKey, CertStatus certStatus,
            ReasonsMask reasonMask, List certPathCerts) throws AnnotatedException
        {
            Date currentDate = new Date(System.currentTimeMillis());
            if (validDate.getTime() > currentDate.getTime())
            {
                throw new AnnotatedException("Validation time is in future.");
            }

            // (a)
            /*
             * We always get timely valid CRLs, so there is no step (a) (1).
             * "locally cached" CRLs are assumed to be in getStore(), additional
             * CRLs must be enabled in the ExtendedPKIXParameters and are in
             * getAdditionalStore()
             */

            Set crls = CertPathValidatorUtilities.getCompleteCRLs(dp, cert,
                currentDate, paramsPKIX);
            boolean validCrlFound = false;
            AnnotatedException lastException = null;
            Iterator crl_iter = crls.iterator();

            while (crl_iter.hasNext()
                && certStatus.getCertStatus() == CertStatus.UNREVOKED
                && !reasonMask.isAllReasons())
            {
                try
                {
                    X509CRL crl = (X509CRL) crl_iter.next();

                    // (d)
                    ReasonsMask interimReasonsMask = processCRLD(crl, dp);

                    // (e)
                    /*
                     * The reasons mask is updated at the end, so only valid CRLs
                     * can update it. If this CRL does not contain new reasons it
                     * must be ignored.
                     */
                    if (!interimReasonsMask.hasNewReasons(reasonMask))
                    {
                        continue;
                    }

                    // (f)
                    Set keys = processCRLF(crl, cert,
                        defaultCRLSignCert, defaultCRLSignKey, paramsPKIX);
                    // (g)
                    PublicKey key = processCRLG(crl, keys);

                    X509CRL deltaCRL = null;

                    if (paramsPKIX.isUseDeltasEnabled())
                    {
                        // get delta CRLs
                        Set deltaCRLs = CertPathValidatorUtilities.getDeltaCRLs(
                            currentDate, paramsPKIX, crl);
                        // we only want one valid delta CRL
                        // (h)
                        deltaCRL = processCRLH(deltaCRLs,
                            key);
                    }

                    /*
                     * CRL must be be valid at the current time, not the validation
                     * time. If a certificate is revoked with reason keyCompromise,
                     * cACompromise, it can be used for forgery, also for the past.
                     * This reason may not be contained in older CRLs.
                     */

                    /*
                     * in the chain model signatures stay valid also after the
                     * certificate has been expired, so they do not have to be in
                     * the CRL vality time
                     */

                    if (paramsPKIX.getValidityModel() != ExtendedPKIXParameters.CHAIN_VALIDITY_MODEL)
                    {
                        /*
                         * if a certificate has expired, but was revoked, it is not
                         * more in the CRL, so it would be regarded as valid if the
                         * first check is not done
                         */
                        if (cert.getNotAfter().getTime() < crl.getThisUpdate()
                            .getTime())
                        {
                            throw new AnnotatedException(
                                "No valid CRL for current time found.");
                        }
                    }

                    processCRLB1(dp, cert, crl);

                    // (b) (2)
                    processCRLB2(dp, cert, crl);

                    // (c)
                    processCRLC(deltaCRL, crl, paramsPKIX);

                    // (i)
                    processCRLI(validDate, deltaCRL, cert.getSerialNumber(),
                        certStatus, paramsPKIX);

                    // (j)
                    processCRLJ(validDate, crl, cert.getSerialNumber(),
                        certStatus);

                    // (k)
                    if (certStatus.getCertStatus() == CRLReason.removeFromCRL)
                    {
                        certStatus.setCertStatus(CertStatus.UNREVOKED);
                    }

                    // update reasons mask
                    reasonMask.addReasons(interimReasonsMask);
                    validCrlFound = true;
                }
                catch (AnnotatedException e)
                {
                    lastException = e;
                }
            }
            if (!validCrlFound)
            {
                throw lastException;
            }
        }

        /**
         * Checks a certificate if it is revoked.
         *
         * @param paramsPKIX PKIX parameters.
         * @param cert Certificate to check if it is revoked.
         * @param validDate The date when the certificate revocation status should
         *            be checked.
         *
         * @param sign The issuer certificate of the certificate <code>cert</code>.
         * @param workingPublicKey The public key of the issuer certificate
         *            <code>sign</code>.
         * @param certPathCerts The certificates of the certification path.
         * @throws AnnotatedException if the certificate is revoked or the status
         *             cannot be checked or some error occurs.
         */
        private static void checkCRLs(ExtendedPKIXParameters paramsPKIX,
            X509Certificate cert, Date validDate, X509Certificate sign,
            PublicKey workingPublicKey, List certPathCerts)
            throws AnnotatedException
        {
            AnnotatedException lastException = null;
            CRLDistPoint crldp = null;
            try
            {
                crldp = CRLDistPoint.getInstance(CertPathValidatorUtilities
                    .getExtensionValue(cert,
                        CRL_DISTRIBUTION_POINTS));
            }
            catch (Exception e)
            {
                throw new AnnotatedException(
                    "CRL distribution point extension could not be read.", e);
            }
            try
            {
                CertPathValidatorUtilities
                    .addAdditionalStoresFromCRLDistributionPoint(crldp, paramsPKIX);
            }
            catch (AnnotatedException e)
            {
                throw new AnnotatedException(
                    "No additional CRL locations could be decoded from CRL distribution point extension.",
                    e);
            }
            CertStatus certStatus = new CertStatus();
            ReasonsMask reasonsMask = new ReasonsMask();

            boolean validCrlFound = false;
            // for each distribution point
            if (crldp != null)
            {
                DistributionPoint dps[] = null;
                try
                {
                    dps = crldp.getDistributionPoints();
                }
                catch (Exception e)
                {
                    throw new AnnotatedException(
                        "Distribution points could not be read.", e);
                }
                try
                {
                    for (int i = 0; i < dps.length
                        && certStatus.getCertStatus() == CertStatus.UNREVOKED
                        && !reasonsMask.isAllReasons(); i++)
                    {
                        ExtendedPKIXParameters paramsPKIXClone = (ExtendedPKIXParameters) paramsPKIX
                            .clone();
                        checkCRL(dps[i], paramsPKIXClone, cert, validDate, sign,
                            workingPublicKey, certStatus, reasonsMask,
                            certPathCerts);
                        validCrlFound = true;
                    }
                }
                catch (AnnotatedException e)
                {
                    lastException = new AnnotatedException(
                        "No valid CRL for distribution point found.", e);
                }
            }

            /*
             * If the revocation status has not been determined, repeat the process
             * above with any available CRLs not specified in a distribution point
             * but issued by the certificate issuer.
             */

            if (certStatus.getCertStatus() == CertStatus.UNREVOKED
                && !reasonsMask.isAllReasons())
            {
                try
                {
                    /*
                     * assume a DP with both the reasons and the cRLIssuer fields
                     * omitted and a distribution point name of the certificate
                     * issuer.
                     */
                    DERObject issuer = null;
                    try
                    {
                        issuer = new ASN1InputStream(CertPathValidatorUtilities
                            .getEncodedIssuerPrincipal(cert).getEncoded())
                            .readObject();
                    }
                    catch (Exception e)
                    {
                        throw new AnnotatedException(
                            "Issuer from certificate for CRL could not be reencoded.",
                            e);
                    }
                    DistributionPoint dp = new DistributionPoint(
                        new DistributionPointName(0, new GeneralNames(
                            new GeneralName(GeneralName.directoryName, issuer))),
                        null, null);
                    ExtendedPKIXParameters paramsPKIXClone = (ExtendedPKIXParameters) paramsPKIX
                        .clone();
                    checkCRL(dp, paramsPKIXClone, cert, validDate, sign,
                        workingPublicKey, certStatus, reasonsMask, certPathCerts);
                    validCrlFound = true;
                }
                catch (AnnotatedException e)
                {
                    lastException = new AnnotatedException(
                        "No valid CRL for distribution point found.", e);
                }
            }

            if (!validCrlFound)
            {
                throw new AnnotatedException("No valid CRL found.", lastException);
            }
            if (certStatus.getCertStatus() != CertStatus.UNREVOKED)
            {
                String message = "Certificate revocation after "
                    + certStatus.getRevocationDate();
                message += ", reason: " + crlReasons[certStatus.getCertStatus()];
                throw new AnnotatedException(message);
            }
            if (!reasonsMask.isAllReasons()
                && certStatus.getCertStatus() == CertStatus.UNREVOKED)
            {
                certStatus.setCertStatus(CertStatus.UNDETERMINED);
            }
            if (certStatus.getCertStatus() == CertStatus.UNDETERMINED)
            {
                throw new AnnotatedException(
                    "Certificate status could not be determined.");
            }
        }
}
