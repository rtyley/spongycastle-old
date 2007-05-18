package org.bouncycastle.jce.provider;

import org.bouncycastle.jce.exception.ExtCertPathBuilderException;

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
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
 * Implements the PKIX CertPathBuilding algorithem for BouncyCastle.
 * <br />
 * <b>MAYBE: implement more CertPath validation whil build path to omit invalid pathes</b>
 *
 * @see CertPathBuilderSpi
 **/
public class PKIXCertPathBuilderSpi
    extends CertPathBuilderSpi
{
    /**
     * Build and validate a CertPath using the given parameter.
     *
     * @param params PKIXBuilderParameters object containing all
     * information to build the CertPath
     **/
    public CertPathBuilderResult engineBuild(
        CertPathParameters params)
        throws CertPathBuilderException, InvalidAlgorithmParameterException 
    {
        if (!(params instanceof PKIXBuilderParameters))
        {
            throw new InvalidAlgorithmParameterException("params must be a PKIXBuilderParameters instance");
        }

        PKIXBuilderParameters pkixParams = (PKIXBuilderParameters)params;

        Collection targets;
        Iterator targetIter;
        List certPathList = new ArrayList();
        Set  certPathSet = new HashSet();
        X509Certificate cert;
        Collection      certs;
        CertPath        certPath = null;
        Exception       certPathException = null;

        // search target certificates
        CertSelector certSelect = pkixParams.getTargetCertConstraints();
        if (certSelect == null)
        {
            throw new CertPathBuilderException("targetCertConstraints must be non-null for CertPath building");
        }

        try
        {
            targets = CertPathValidatorUtilities.findCertificates(certSelect, pkixParams.getCertStores());
        }
        catch (AnnotatedException e)
        {
            throw new ExtCertPathBuilderException("Error finding target certificate.", e.getCause());
        }

        if (targets.isEmpty())
        {
            throw new CertPathBuilderException("no certificate found matching targetCertContraints");
        }

        CertificateFactory  cFact;
        CertPathValidator   validator;

        try
        {
            cFact = CertificateFactory.getInstance("X.509", "BC");
            validator = CertPathValidator.getInstance("PKIX", "BC");
        }
        catch (Exception e)
        {
            throw new CertPathBuilderException("exception creating support classes: " + e);
        }

        //
        // check all potential target certificates
        targetIter = targets.iterator();
        while (targetIter.hasNext())
        {
            cert = (X509Certificate)targetIter.next();
            certPathList.clear();
            certPathSet.clear();
            while (cert != null)
            {
                // add cert to the certpath
                certPathList.add(cert);
                certPathSet.add(cert);

                // check whether the issuer of <cert> is a TrustAnchor
                if (findTrustAnchor(cert, pkixParams.getTrustAnchors()) != null)
                {
                    try
                    {
                        certPath = cFact.generateCertPath(certPathList);

                        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)validator.validate(certPath, pkixParams);

                        return new PKIXCertPathBuilderResult(certPath,
                                     result.getTrustAnchor(),
                                     result.getPolicyTree(),
                                     result.getPublicKey());
                    }
                    catch (CertificateException ex)
                    {
                        certPathException = ex;
                    }
                    catch (CertPathValidatorException ex)
                    {
                        certPathException = ex;
                    }
                    // if validation failed go to next certificate
                    cert = null;
                }
                else
                {
                    // try to get the issuer certificate from one
                    // of the CertStores
                    try
                    {
                        X509Certificate issuer = findIssuer(cert, pkixParams.getCertStores());
                        if (issuer.equals(cert))
                        {
                            cert = null;
                        }
                        else
                        {
                            cert = issuer;
                            // validation failed - circular path detected, go to next certificate
                            if (certPathSet.contains(cert))
                            {
                                cert = null;
                            }
                        }
                    }
                    catch (CertPathValidatorException ex)
                    {
                        certPathException = ex;
                        cert = null;
                    }
                }
            }
        }

        if (certPath != null)
        {
            throw new CertPathBuilderException("found certificate chain, but could not be validated", certPathException);
        }

        throw new CertPathBuilderException("unable to find certificate chain");
    }

    /**
     * Search the given Set of TrustAnchor's for one that is the
     * issuer of the fiven X509 certificate.
     *
     * @param cert the X509 certificate
     * @param trustAnchors a Set of TrustAnchor's
     *
     * @return the <code>TrustAnchor</code> object if found or
     * <code>null</code> if not.
     *
     */
    final TrustAnchor findTrustAnchor(
        X509Certificate cert,
        Set             trustAnchors) 
        throws CertPathBuilderException
    {
        Iterator iter = trustAnchors.iterator();
        TrustAnchor trust = null;
        PublicKey trustPublicKey = null;
        Exception invalidKeyEx = null;

        X509CertSelector certSelectX509 = new X509CertSelector();

        try
        {
            certSelectX509.setSubject(cert.getIssuerX500Principal().getEncoded());
        }
        catch (IOException ex)
        {
            throw new CertPathBuilderException("can't get trust anchor principal",null);
        }

        while (iter.hasNext() && trust == null)
        {
            trust = (TrustAnchor)iter.next();
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
                    X500Principal caName = new X500Principal(trust.getCAName());
                    if (certIssuer.equals(caName))
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
            throw new CertPathBuilderException("TrustAnchor found put certificate validation failed",invalidKeyEx);
        }

        return trust;
    }
    
    /**
     * Find the issuer certificate of the given certificate.
     *
     * @param cert the certificate hows issuer certificate should
     * be found.
     * @param certStores a list of <code>CertStore</code> object
     * that will be searched
     *
     * @return then <code>X509Certificate</code> object containing
     * the issuer certificate or <code>null</code> if not found
     *
     * @exception CertPathValidatorException if a TrustAnchor  was
     * found but the signature verificytion on the given certificate
     * has thrown an exception. This Exception can be obtainted with
     * <code>getCause()</code> method.
     **/
    private X509Certificate findIssuer(
        X509Certificate cert,
        List certStores)
        throws CertPathValidatorException
    {
        Exception invalidKeyEx = null;
        X509CertSelector certSelect = new X509CertSelector();
        try
        {
            certSelect.setSubject(cert.getIssuerX500Principal().getEncoded());
        }
        catch (IOException ex)
        {
            throw new CertPathValidatorException("Issuer not found", null, null, -1);
        }

        Iterator iter;
        try
        {
            iter = CertPathValidatorUtilities.findCertificates(certSelect, certStores).iterator();
        }
        catch (AnnotatedException e)
        {
            throw new CertPathValidatorException(e.getCause());
        }
        
        X509Certificate issuer = null;
        while (iter.hasNext() && issuer == null)
        {
            issuer = (X509Certificate)iter.next();
            try
            {
                cert.verify(issuer.getPublicKey());
            }
            catch (Exception ex)
            {
                invalidKeyEx = ex;
                issuer = null;
            }
        }

        if (issuer == null && invalidKeyEx == null)
        {
           throw new CertPathValidatorException("Issuer not found", null, null, -1);
        }

        if (issuer == null && invalidKeyEx != null)
        {
            throw new CertPathValidatorException("issuer found but certificate validation failed",invalidKeyEx,null,-1);
        }

        return issuer;
    }
}
