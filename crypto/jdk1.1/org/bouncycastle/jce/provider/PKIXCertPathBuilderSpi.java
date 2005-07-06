package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;

/**
 * Implements the PKIX CertPathBuilding algorithem for BouncyCastle.<br />
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

        Iterator iter;
        Collection targets;
        Iterator targetIter;
        List certPathList = new ArrayList();
        TrustAnchor trust = null;
        X509Certificate cert;
        X509CertSelector certSelectX509 = null;
        Collection certs;
        CertPath certPath = null;
        CertPathValidatorException certPathException = null;

        try
        {
            // search target certificates
            CertSelector certSelect = pkixParams.getTargetCertConstraints();
            if ( certSelect == null )
            throw new CertPathBuilderException("targetCertConstraints must be non-null for CertPath building");
            targets = findCertificates(certSelect, pkixParams.getCertStores() );
            if ( targets.isEmpty() )
            throw new CertPathBuilderException("no certificate found matching targetCertContraints");

            // check all potential target certificates
            targetIter = targets.iterator();
            while ( targetIter.hasNext() )
            {
                cert = (X509Certificate)targetIter.next();
                certPathList.clear();
                while ( cert != null )
                {
                    // add cert to the certpath
                    certPathList.add( cert );

                    // check wether the issuer of <cert> is a TrustAnchor 
                    if (findTrustAnchor(cert, pkixParams.getTrustAnchors()) != null)
                    {
                        try
                        {
                            certPath = CertificateFactory.getInstance("X.509", "BC").generateCertPath( certPathList );
                            CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
                            PKIXCertPathValidatorResult result =
                            (PKIXCertPathValidatorResult) validator.validate(certPath, pkixParams);
                            return new PKIXCertPathBuilderResult(certPath,
                                         result.getTrustAnchor(),
                                         result.getPolicyTree(),
                                         result.getPublicKey() );
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
        }
        catch (Exception ex)
        {
            throw new CertPathBuilderException( 
                "Exception thrown while doing CertPath building\n", ex );
        }

        if (certPath != null)
        {
            throw new CertPathBuilderException("found certifiacte chain, but could not be validated", certPathException);
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
     * @exception CertPathValidatorException if a TrustAnchor  was
     * found but the signature verificytion on the given certificate
     * has thrown an exception. This Exception can be obtainted with
     * <code>getCause()</code> method.
     **/
    static final TrustAnchor findTrustAnchor(
        X509Certificate cert,
        Set             trustAnchors) 
        throws CertPathValidatorException
    {
        Iterator iter = trustAnchors.iterator();
        TrustAnchor trust = null;
        PublicKey trustPublicKey = null;
        Exception invalidKeyEx = null;

        X509CertSelector certSelectX509 = new X509CertSelector();

        try
        {
            certSelectX509.setSubject(((X509Principal)cert.getIssuerDN()).getEncoded());
        }
        catch (IOException ex)
        {
             throw new CertPathValidatorException("can't get trust anchor principal",null);
        }

        while ( iter.hasNext() && trust == null )
        {
            trust = (TrustAnchor)iter.next();
            if ( trust.getTrustedCert() != null )
            {
                if ( certSelectX509.match(trust.getTrustedCert()) )
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
                    X509Name certIssuer = new X509Name(trimX509Name(cert.getIssuerDN().getName()));
                    X509Name caName = new X509Name(trimX509Name(trust.getCAName()));
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
            throw new CertPathValidatorException("TrustAnchor found put certificate validation failed",invalidKeyEx,null,-1);
        }

        return trust;
    }

    /**
     * Return a Collection of all certificates found in the
     * CertStore's that are matching the certSelect criteriums.
     *
     * @param certSelector a {@link CertSelector CertSelector}
     * object that will be used to select the certificates
     * @param certStores a List containing only {@link CertStore
     * CertStore} objects. These are used to search for
     * certificates
     *
     * @return a Collection of all found {@link Certificate Certificate}
     * objects. May be emtpy but never <code>null</code>.
     **/
    private static final Collection findCertificates(
        CertSelector certSelect,
        List certStores)
    {
        Set certs = new HashSet();
        Iterator iter = certStores.iterator();
        CertStore certStore;
        while (iter.hasNext())
        {
            certStore = (CertStore)iter.next();
            try
            {
                certs.addAll(certStore.getCertificates(certSelect));
            }
            catch (CertStoreException ex)
            {
                ex.printStackTrace();
            }
        }
        return certs;
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
    private static final X509Certificate findIssuer(
        X509Certificate cert,
        List certStores)
        throws CertPathValidatorException
    {
        Exception invalidKeyEx = null;
        X509CertSelector certSelect = new X509CertSelector();
        try
        {
            certSelect.setSubject(((X509Principal)cert.getIssuerDN()).getEncoded());
        }
        catch (IOException ex)
        {
            throw new CertPathValidatorException("Issuer not found", null, null, -1);
        }

        Iterator iter = findCertificates(certSelect, certStores).iterator();
        X509Certificate issuer = null;
        while ( iter.hasNext() && issuer == null )
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

        if ( issuer == null && invalidKeyEx == null )
        {
            throw new CertPathValidatorException("issuer not found",null,null,-1);
        }

        if ( issuer == null && invalidKeyEx != null )
        {
            throw new CertPathValidatorException("issuer found but certificate validation failed",invalidKeyEx,null,-1);
        }

        return issuer;
    }

    /**
     * Returns the given name converted to upper case and all multi spaces squezed
     * to one space.
     **/
    static String trimX509Name(String name)
    {
        String data = name.trim().toUpperCase();
        int pos;
        while ((pos = data.indexOf("  ")) >= 0)
        {
            data = data.substring(0,pos) + data.substring(pos+1);
        }
        while ((pos = data.indexOf(" =")) >= 0)
        {
            data = data.substring(0,pos) + data.substring(pos+1);
        }
        while ((pos = data.indexOf("= ")) >= 0)
        {
            data = data.substring(0,pos+1) + data.substring(pos+2);
        }
        return data;
    }
}
