package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.x509.ExtendedPKIXParameters;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509CRLStoreSelector;
import org.bouncycastle.x509.X509Store;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CertPathValidatorUtilities
{
    protected static final String CERTIFICATE_POLICIES = X509Extensions.CertificatePolicies.getId();
    protected static final String BASIC_CONSTRAINTS = X509Extensions.BasicConstraints.getId();
    protected static final String POLICY_MAPPINGS = X509Extensions.PolicyMappings.getId();
    protected static final String SUBJECT_ALTERNATIVE_NAME = X509Extensions.SubjectAlternativeName.getId();
    protected static final String NAME_CONSTRAINTS = X509Extensions.NameConstraints.getId();
    protected static final String KEY_USAGE = X509Extensions.KeyUsage.getId();
    protected static final String INHIBIT_ANY_POLICY = X509Extensions.InhibitAnyPolicy.getId();
    protected static final String ISSUING_DISTRIBUTION_POINT = X509Extensions.IssuingDistributionPoint.getId();
    protected static final String DELTA_CRL_INDICATOR = X509Extensions.DeltaCRLIndicator.getId();
    protected static final String POLICY_CONSTRAINTS = X509Extensions.PolicyConstraints.getId();
    protected static final String FRESHEST_CRL = X509Extensions.FreshestCRL.getId();
    protected static final String CRL_DISTRIBUTION_POINTS = X509Extensions.CRLDistributionPoints.getId();
    protected static final String AUTHORITY_KEY_IDENTIFIER = X509Extensions.AuthorityKeyIdentifier.getId();

    protected static final String ANY_POLICY = "2.5.29.32.0";
    
    protected static final String CRL_NUMBER = X509Extensions.CRLNumber.getId();
    
    /*
     * key usage bits
     */
    protected static final int    KEY_CERT_SIGN = 5;
    protected static final int    CRL_SIGN = 6;

    protected static final String[] crlReasons = new String[] {
        "unspecified",
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "unknown",
        "removeFromCRL",
        "privilegeWithdrawn",
        "aACompromise" };
    
    /**
     * Search the given Set of TrustAnchor's for one that is the
     * issuer of the given X509 certificate.
     *
     * @param cert the X509 certificate
     * @param trustAnchors a Set of TrustAnchor's
     *
     * @return the <code>TrustAnchor</code> object if found or
     * <code>null</code> if not.
     *
     * @exception CertPathValidatorException if a TrustAnchor  was
     * found but the signature verification on the given certificate
     * has thrown an exception. This Exception can be obtainted with
     * <code>getCause()</code> method.
     **/
    protected static final TrustAnchor findTrustAnchor(
        X509Certificate cert,
        CertPath        certPath,
        int             index,
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
            certSelectX509.setSubject(getEncodedIssuerPrincipal(cert).getEncoded());
        }
        catch (IOException ex)
        {
            throw new CertPathValidatorException(ex);
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
                    X500Principal certIssuer = getEncodedIssuerPrincipal(cert);
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
            throw new CertPathValidatorException("TrustAnchor found but certificate validation failed.", invalidKeyEx, certPath, index);
        }

        return trust;
    }

    /**
     * Returns the issuer of an attribute certificate or certificate.
     * @param cert The attribute certificate or certificate.
     * @return The issuer as <code>X500Principal</code>.
     */
    protected static X500Principal getEncodedIssuerPrincipal(
        Object cert)
    {
        if (cert instanceof X509Certificate)
        {
            return ((X509Certificate)cert).getIssuerX500Principal();
        }
        else
        {
            return (X500Principal)((X509AttributeCertificate)cert).getIssuer().getPrincipals()[0];
        }
    }

    protected static Date getValidDate(PKIXParameters paramsPKIX)
    {
        Date validDate = paramsPKIX.getDate();

        if (validDate == null)
        {
            validDate = new Date();
        }

        return validDate;
    }

    protected static X500Principal getSubjectPrincipal(X509Certificate cert)
    {
        return cert.getSubjectX500Principal();
    }
    
    protected static boolean isSelfIssued(X509Certificate cert)
    {
        return cert.getSubjectDN().equals(cert.getIssuerDN());
    }
    
    
    /**
     * extract the value of the given extension, if it exists.
     */
    protected static DERObject getExtensionValue(
        java.security.cert.X509Extension    ext,
        String                              oid)
        throws AnnotatedException
    {
        byte[]  bytes = ext.getExtensionValue(oid);
        if (bytes == null)
        {
            return null;
        }

        return getObject(oid, bytes);
    }
    
    private static DERObject getObject(
            String oid,
            byte[] ext)
            throws AnnotatedException
    {
        try
        {
            ASN1InputStream aIn = new ASN1InputStream(ext);
            ASN1OctetString octs = (ASN1OctetString)aIn.readObject();

            aIn = new ASN1InputStream(octs.getOctets());
            return aIn.readObject();
        }
        catch (IOException e)
        {
            throw new AnnotatedException("exception processing extension " + oid, e);
        }
    }
    
    protected static X500Principal getIssuerPrincipal(X509CRL crl)
    {
        return crl.getIssuerX500Principal();
    }
    
    protected static AlgorithmIdentifier getAlgorithmIdentifier(
        PublicKey key)
        throws CertPathValidatorException
    {
        try
        {
            ASN1InputStream      aIn = new ASN1InputStream(key.getEncoded());

            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(aIn.readObject());

            return info.getAlgorithmId();
        }
        catch (IOException e)
        {
            throw new CertPathValidatorException("exception processing public key");
        }
    }

    //
    // Utility functions for name constraint checking
    //

    private static boolean withinDNSubtree(ASN1Sequence dns, ASN1Sequence subtree)
    {
        if (subtree.size() < 1)
        {
            return false;
        }

        if (subtree.size() > dns.size())
        {
            return false;
        }

        for (int j = subtree.size() - 1; j >= 0; j--)
        {
            if (!subtree.getObjectAt(j).equals(dns.getObjectAt(j)))
            {
                return false;
            }
        }

        return true;
    }

    protected static void checkPermittedDN(Set permitted, ASN1Sequence dns)
            throws CertPathValidatorException
    {
        if (permitted.isEmpty())
        {
            return;
        }

        Iterator it = permitted.iterator();

        while (it.hasNext())
        {
            ASN1Sequence subtree = (ASN1Sequence) it.next();

            if (withinDNSubtree(dns, subtree))
            {
                return;
            }
        }

        throw new CertPathValidatorException(
                "Subject distinguished name is not from a permitted subtree");
    }

    protected static void checkExcludedDN(Set excluded, ASN1Sequence dns)
            throws CertPathValidatorException
    {
        if (excluded.isEmpty())
        {
            return;
        }

        Iterator it = excluded.iterator();

        while (it.hasNext())
        {
            ASN1Sequence subtree = (ASN1Sequence) it.next();

            if (withinDNSubtree(dns, subtree))
            {
                throw new CertPathValidatorException(
                        "Subject distinguished name is from an excluded subtree");
            }
        }
    }

    protected static Set intersectDN(Set permitted, ASN1Sequence dn)
    {
        if (permitted.isEmpty())
        {
            permitted.add(dn);

            return permitted;
        }
        else
        {
            Set intersect = new HashSet();

            Iterator _iter = permitted.iterator();
            while (_iter.hasNext())
            {
                ASN1Sequence subtree = (ASN1Sequence) _iter.next();

                if (withinDNSubtree(dn, subtree))
                {
                    intersect.add(dn);
                }
                else if (withinDNSubtree(subtree, dn))
                {
                    intersect.add(subtree);
                }
            }

            return intersect;
        }
    }

    protected static Set unionDN(Set excluded, ASN1Sequence dn)
    {
        if (excluded.isEmpty())
        {
            excluded.add(dn);

            return excluded;
        }
        else
        {
            Set intersect = new HashSet();

            Iterator _iter = excluded.iterator();
            while (_iter.hasNext())
            {
                ASN1Sequence subtree = (ASN1Sequence) _iter.next();

                if (withinDNSubtree(dn, subtree))
                {
                    intersect.add(subtree);
                }
                else if (withinDNSubtree(subtree, dn))
                {
                    intersect.add(dn);
                }
                else
                {
                    intersect.add(subtree);
                    intersect.add(dn);
                }
            }

            return intersect;
        }
    }

    protected static Set intersectEmail(Set permitted, String email)
    {
        String _sub = email.substring(email.indexOf('@') + 1);

        if (permitted.isEmpty())
        {
            permitted.add(_sub);

            return permitted;
        }
        else
        {
            Set intersect = new HashSet();

            Iterator _iter = permitted.iterator();
            while (_iter.hasNext())
            {
                String _permitted = (String) _iter.next();

                if (_sub.endsWith(_permitted))
                {
                    intersect.add(_sub);
                }
                else if (_permitted.endsWith(_sub))
                {
                    intersect.add(_permitted);
                }
            }

            return intersect;
        }
    }

    protected static Set unionEmail(Set excluded, String email)
    {
        String _sub = email.substring(email.indexOf('@') + 1);

        if (excluded.isEmpty())
        {
            excluded.add(_sub);
            return excluded;
        }
        else
        {
            Set intersect = new HashSet();

            Iterator _iter = excluded.iterator();
            while (_iter.hasNext())
            {
                String _excluded = (String) _iter.next();

                if (_sub.endsWith(_excluded))
                {
                    intersect.add(_excluded);
                }
                else if (_excluded.endsWith(_sub))
                {
                    intersect.add(_sub);
                }
                else
                {
                    intersect.add(_excluded);
                    intersect.add(_sub);
                }
            }

            return intersect;
        }
    }

    protected static Set intersectIP(Set permitted, byte[] ip)
    {
        // TBD
        return permitted;
    }

    protected static Set unionIP(Set excluded, byte[] ip)
    {
        // TBD
        return excluded;
    }

    protected static void checkPermittedEmail(Set permitted, String email)
            throws CertPathValidatorException
    {
        if (permitted.isEmpty())
        {
            return;
        }

        String sub = email.substring(email.indexOf('@') + 1);
        Iterator it = permitted.iterator();

        while (it.hasNext())
        {
            String str = (String) it.next();

            if (sub.endsWith(str))
            {
                return;
            }
        }

        throw new CertPathValidatorException(
                "Subject email address is not from a permitted subtree");
    }

    protected static void checkExcludedEmail(Set excluded, String email)
            throws CertPathValidatorException
    {
        if (excluded.isEmpty())
        {
            return;
        }

        String sub = email.substring(email.indexOf('@') + 1);
        Iterator it = excluded.iterator();

        while (it.hasNext())
        {
            String str = (String) it.next();
            if (sub.endsWith(str))
            {
                throw new CertPathValidatorException(
                        "Subject email address is from an excluded subtree");
            }
        }
    }

    protected static void checkPermittedIP(Set permitted, byte[] ip)
            throws CertPathValidatorException
    {
        if (permitted.isEmpty())
        {
            return;
        }

        // TODO: ??? Something here
    }

    protected static void checkExcludedIP(Set excluded, byte[] ip)
            throws CertPathValidatorException
    {
        if (excluded.isEmpty())
        {
            return;
        }

        // TODO, check RFC791 and RFC1883 for IP bytes definition.
    }
    
    
    // crl checking
    
    /**
     * Return a Collection of all CRLs found in the
     * CertStore's that are matching the crlSelect criteriums.
     *
     * @param crlSelect a {@link CertSelector CertSelector}
     * object that will be used to select the CRLs
     * @param crlStores a List containing only {@link CertStore
     * CertStore} objects. These are used to search for
     * CRLs
     *
     * @return a Collection of all found {@link CRL CRL}
     * objects. May be empty but never <code>null</code>.
     */
    protected static final Collection findCRLs(
        X509CRLSelector crlSelect,
        List            crlStores)
        throws AnnotatedException
    {
        Set crls = new HashSet();
        Iterator iter = crlStores.iterator();
    
        while (iter.hasNext())
        {
            CertStore   certStore = (CertStore)iter.next();
    
            try
            {
                crls.addAll(certStore.getCRLs(crlSelect));
            }
            catch (CertStoreException e)
            {
                throw new AnnotatedException("cannot extract crl: " + e, e);
            }
        }
    
        return crls;
    }
    
    /**
     * Return a Collection of all CRLs found in the X509Store's that are
     * matching the crlSelect criteriums.
     *
     * @param crlSelect a {@link X509CRLStoreSelector} object that will be used
     *            to select the CRLs
     * @param crlStores a List containing only
     *            {@link org.bouncycastle.x509.X509Store  X509Store} objects.
     *            These are used to search for CRLs
     *
     * @return a Collection of all found {@link X509CRL X509CRL} objects. May be
     *         empty but never <code>null</code>.
     */
    protected static final Collection findCRLs(X509CRLStoreSelector crlSelect,
        List crlStores) throws AnnotatedException
    {
        Set crls = new HashSet();
        Iterator iter = crlStores.iterator();

        AnnotatedException lastException = null;
        boolean foundValidStore = false;

        while (iter.hasNext())
        {
            X509Store store = (X509Store) iter.next();

            try
            {
                crls.addAll(store.getMatches(crlSelect));
                foundValidStore = true;
            }
            catch (StoreException e)
            {
                lastException = new AnnotatedException(
                    "Exception searching in X.509 CRL store.", e);
            }
        }
        if (!foundValidStore && lastException != null)
        {
            throw lastException;
        }
        return crls;
    }

    //
    // policy checking
    // 
    
    protected static final Set getQualifierSet(ASN1Sequence qualifiers) 
        throws CertPathValidatorException
    {
        Set             pq   = new HashSet();
        
        if (qualifiers == null)
        {
            return pq;
        }
        
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
    
        Enumeration e = qualifiers.getObjects();
    
        while (e.hasMoreElements())
        {
            try
            {
                aOut.writeObject(e.nextElement());
    
                pq.add(new PolicyQualifierInfo(bOut.toByteArray()));
            }
            catch (IOException ex)
            {
                throw new CertPathValidatorException("exception building qualifier set: " + ex);
            }
    
            bOut.reset();
        }
        
        return pq;
    }
    
    protected static PKIXPolicyNode removePolicyNode(
        PKIXPolicyNode  validPolicyTree,
        List     []        policyNodes,
        PKIXPolicyNode _node)
    {
        PKIXPolicyNode _parent = (PKIXPolicyNode)_node.getParent();
        
        if (validPolicyTree == null)
        {
            return null;
        }

        if (_parent == null)
        {
            for (int j = 0; j < policyNodes.length; j++)
            {
                policyNodes[j] = new ArrayList();
            }

            return null;
        }
        else
        {
            _parent.removeChild(_node);
            removePolicyNodeRecurse(policyNodes, _node);

            return validPolicyTree;
        }
    }
    
    private static void removePolicyNodeRecurse(
        List     []        policyNodes,
        PKIXPolicyNode  _node)
    {
        policyNodes[_node.getDepth()].remove(_node);

        if (_node.hasChildren())
        {
            Iterator _iter = _node.getChildren();
            while (_iter.hasNext())
            {
                PKIXPolicyNode _child = (PKIXPolicyNode)_iter.next();
                removePolicyNodeRecurse(policyNodes, _child);
            }
        }
    }
    
    
    protected static boolean processCertD1i(
        int                 index,
        List     []            policyNodes,
        DERObjectIdentifier pOid,
        Set                 pq)
    {
        List       policyNodeVec = policyNodes[index - 1];

        for (int j = 0; j < policyNodeVec.size(); j++)
        {
            PKIXPolicyNode node = (PKIXPolicyNode)policyNodeVec.get(j);
            Set            expectedPolicies = node.getExpectedPolicies();
            
            if (expectedPolicies.contains(pOid.getId()))
            {
                Set childExpectedPolicies = new HashSet();
                childExpectedPolicies.add(pOid.getId());
                
                PKIXPolicyNode child = new PKIXPolicyNode(new ArrayList(),
                                                           index,
                                                           childExpectedPolicies,
                                                           node,
                                                           pq,
                                                           pOid.getId(),
                                                           false);
                node.addChild(child);
                policyNodes[index].add(child);
                
                return true;
            }
        }
        
        return false;
    }

    protected static void processCertD1ii(
        int                 index,
        List     []            policyNodes,
        DERObjectIdentifier _poid,
        Set _pq)
    {
        List       policyNodeVec = policyNodes[index - 1];

        for (int j = 0; j < policyNodeVec.size(); j++)
        {
            PKIXPolicyNode _node = (PKIXPolicyNode)policyNodeVec.get(j);
            Set            _expectedPolicies = _node.getExpectedPolicies();
            
            if (ANY_POLICY.equals(_node.getValidPolicy()))
            {
                Set _childExpectedPolicies = new HashSet();
                _childExpectedPolicies.add(_poid.getId());
                
                PKIXPolicyNode _child = new PKIXPolicyNode(new ArrayList(),
                                                           index,
                                                           _childExpectedPolicies,
                                                           _node,
                                                           _pq,
                                                           _poid.getId(),
                                                           false);
                _node.addChild(_child);
                policyNodes[index].add(_child);
                return;
            }
        }
    }
    
    protected static void prepareNextCertB1(
            int i,
            List[] policyNodes,
            String id_p,
            Map m_idp,
            X509Certificate cert
            ) throws AnnotatedException,CertPathValidatorException
    {
        boolean idp_found = false;
        Iterator nodes_i = policyNodes[i].iterator();
        while (nodes_i.hasNext())
        {
            PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
            if (node.getValidPolicy().equals(id_p))
            {
                idp_found = true;
                node.expectedPolicies = (Set)m_idp.get(id_p);
                break;
            }
        }

        if (!idp_found)
        {
            nodes_i = policyNodes[i].iterator();
            while (nodes_i.hasNext())
            {
                PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
                if (ANY_POLICY.equals(node.getValidPolicy()))
                {
                    Set pq = null;
                    ASN1Sequence policies = (ASN1Sequence)getExtensionValue(cert, CERTIFICATE_POLICIES);
                    Enumeration e = policies.getObjects();
                    while (e.hasMoreElements())
                    {
                        PolicyInformation pinfo = PolicyInformation.getInstance(e.nextElement());
                        if (ANY_POLICY.equals(pinfo.getPolicyIdentifier().getId()))
                        {
                            pq = getQualifierSet(pinfo.getPolicyQualifiers());
                            break;
                        }
                    }
                    boolean ci = false;
                    if (cert.getCriticalExtensionOIDs() != null)
                    {
                        ci = cert.getCriticalExtensionOIDs().contains(CERTIFICATE_POLICIES);
                    }

                    PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
                    if (ANY_POLICY.equals(p_node.getValidPolicy()))
                    {
                        PKIXPolicyNode c_node = new PKIXPolicyNode(
                                new ArrayList(), i,
                                (Set)m_idp.get(id_p),
                                p_node, pq, id_p, ci);
                        p_node.addChild(c_node);
                        policyNodes[i].add(c_node);
                    }
                    break;
                }
            }
        }
    }
    
    protected static PKIXPolicyNode prepareNextCertB2(
            int i,
            List[] policyNodes,
            String id_p,
            PKIXPolicyNode validPolicyTree) 
    {
        Iterator nodes_i = policyNodes[i].iterator();
        while (nodes_i.hasNext())
        {
            PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
            if (node.getValidPolicy().equals(id_p))
            {
                PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
                p_node.removeChild(node);
                nodes_i.remove();
                for (int k = (i - 1); k >= 0; k--)
                {
                    List nodes = policyNodes[k];
                    for (int l = 0; l < nodes.size(); l++)
                    {
                        PKIXPolicyNode node2 = (PKIXPolicyNode)nodes.get(l);
                        if (!node2.hasChildren())
                        {
                            validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node2);
                            if (validPolicyTree == null)
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }
        return validPolicyTree;
    }
    
    protected static boolean isAnyPolicy(
        Set policySet)
    {
        return policySet == null || policySet.contains(ANY_POLICY) || policySet.isEmpty();
    }
    
    protected static void addAdditionalStoreFromLocation(String location,
        ExtendedPKIXParameters pkixParams)
    {
        if (pkixParams.isAdditionalLocationsEnabled())
        {
            try
            {
                if (location.startsWith("ldap://"))
                {
                    // ldap://directory.d-trust.net/CN=D-TRUST
                    // Qualified CA 2003 1:PN,O=D-Trust GmbH,C=DE
                    // skip "ldap://"
                    location = location.substring(7);
                    // after first / baseDN starts
                    String base = null;
                    String url = null;
                    if (location.indexOf("/") != -1)
                    {
                        base = location.substring(location.indexOf("/"));
                        // URL
                        url = "ldap://"
                            + location.substring(0, location.indexOf("/"));
                    }
                    else
                    {
                        url = "ldap://" + location;
                    }
                    // use all purpose parameters
                    X509LDAPCertStoreParameters params = new X509LDAPCertStoreParameters.Builder(
                        url, base).build();
                    pkixParams.addAddionalStore(X509Store.getInstance(
                        "CERTIFICATE/LDAP", params, "BC"));
                    pkixParams.addAddionalStore(X509Store.getInstance(
                        "CRL/LDAP", params, "BC"));
                    pkixParams.addAddionalStore(X509Store.getInstance(
                        "ATTRIBUTECERTIFICATE/LDAP", params, "BC"));
                    pkixParams.addAddionalStore(X509Store.getInstance(
                        "CERTIFICATEPAIR/LDAP", params, "BC"));
                }
            }
            catch (Exception e)
            {
                // cannot happen
                throw new RuntimeException("Exception adding X.509 stores.");
            }
        }
    }

    /**
     * Return a Collection of all certificates found in the CertStore's that are
     * matching the certSelect criteriums.
     *
     * @param certSelect a {@link CertSelector CertSelector} object that will
     *            be used to select the certificates
     * @param certStores a List containing only {@link CertStore CertStore}
     *            objects. These are used to search for certificates
     *
     * @return a Collection of all found {@link java.security.cert.Certificate Certificate}
     *         objects. May be empty but never <code>null</code>.
     */
    protected static Collection findCertificates(CertSelector certSelect,
        List certStores) throws AnnotatedException
    {
        Set certs = new HashSet();
        Iterator iter = certStores.iterator();

        while (iter.hasNext())
        {
            CertStore certStore = (CertStore) iter.next();

            try
            {
                certs.addAll(certStore.getCertificates(certSelect));
            }
            catch (CertStoreException e)
            {
                throw

                new AnnotatedException(
                    "Problem while picking certificates from certificate store.",
                    e);
            }
        }

        return certs;
    }

    /**
     * Return a Collection of all certificates or attribute certificates found
     * in the X509Store's that are matching the certSelect criteriums.
     *
     * @param certSelect a {@link Selector} object that will be used to select
     *            the certificates
     * @param certStores a List containing only {@link X509Store} objects. These
     *            are used to search for certificates.
     *
     * @return a Collection of all found {@link X509Certificate} or
     *         {@link org.bouncycastle.x509.X509AttributeCertificate} objects.
     *         May be empty but never <code>null</code>.
     */
    protected static Collection findCertificates(Selector certSelect,
        List certStores) throws AnnotatedException
    {
        Set certs = new HashSet();
        Iterator iter = certStores.iterator();

        while (iter.hasNext())
        {
            X509Store certStore = (X509Store) iter.next();
            try
            {
                certs.addAll(certStore.getMatches(certSelect));
            }
            catch (StoreException e)
            {
                throw

                new AnnotatedException(
                    "Problem while picking certificates from X.509 store.", e);
            }
        }
        return certs;
    }

    protected static void addAdditionalStoresFromCRLDistributionPoint(
        CRLDistPoint crldp, ExtendedPKIXParameters pkixParams)
        throws AnnotatedException
    {
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
            for (int i = 0; i < dps.length; i++)
            {
                DistributionPointName dpn = dps[i].getDistributionPoint();
                // look for URIs in fullName
                if (dpn.getType() == DistributionPointName.FULL_NAME)
                {
                    GeneralName[] genNames = GeneralNames.getInstance(
                        dpn.getName()).getNames();
                    // look for an URI
                    for (int j = 0; j < genNames.length; j++)
                    {
                        if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier)
                        {
                            String location = DERIA5String.getInstance(
                                genNames[j].getName()).getString();
                            CertPathValidatorUtilities
                                .addAdditionalStoreFromLocation(location,
                                    pkixParams);
                        }
                    }
                }
            }
        }
    }

    /**
     * Add the CRL issuers from the cRLIssuer field of the distribution point or
     * from the certificate if not given to the issuer criterion of the
     * <code>selector</code>.
     * <p>
     * The <code>issuerPrincipals</code> are a collection with a single
     * <code>X500Principal</code> for <code>X509Certificate</code>s. For
     * {@link X509AttributeCertificate}s the issuer may contain more than one
     * <code>X500Principal</code>.
     *
     * @param dp The distribution point.
     * @param issuerPrincipals The issuers of the certificate or atribute
     *            certificate which contains the distribution point.
     * @param selector The CRL selector.
     * @param pkixParams The PKIX parameters containing the cert stores.
     * @throws AnnotatedException if an exception occurs while processing.
     * @throws ClassCastException if <code>issuerPrincipals</code> does not
     * contain only <code>X500Principal</code>s.
     */
    protected static void getCRLIssuersFromDistributionPoint(
        DistributionPoint dp, Collection issuerPrincipals,
        X509CRLStoreSelector selector, ExtendedPKIXParameters pkixParams)
        throws AnnotatedException
    {
        List issuers = new ArrayList();
        // indirect CRL
        if (dp.getCRLIssuer() != null)
        {
            GeneralName genNames[] = dp.getCRLIssuer().getNames();
            // look for a DN
            for (int j = 0; j < genNames.length; j++)
            {
                if (genNames[j].getTagNo() == GeneralName.directoryName)
                {
                    try
                    {
                        issuers.add(new X500Principal(genNames[j].getName()
                            .getDERObject().getEncoded()));
                    }
                    catch (IOException e)
                    {
                        throw new AnnotatedException(
                            "CRL issuer information from distribution point cannot be decoded.",
                            e);
                    }
                }
            }
        }
        else
        {
            /*
             * certificate issuer is CRL issuer, distributionPoint field MUST be
             * present.
             */
            if (dp.getDistributionPoint() == null)
            {
                throw new AnnotatedException(
                    "CRL issuer is omitted from distribution point but no distributionPoint field present.");
            }
            // add and check issuer principals
            for (Iterator it=issuerPrincipals.iterator(); it.hasNext();)
            {
                issuers.add((X500Principal)it.next());
            }
        }
        // distributionPoint
        if (dp.getDistributionPoint() != null)
        {
            // look for nameRelativeToCRLIssuer
            if (dp.getDistributionPoint().getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
            {
                // append fragment to issuer, only one
                // issuer can be there, if this is given
                if (issuers.size() != 1)
                {
                    throw new AnnotatedException(
                        "nameRelativeToCRLIssuer field is given but more than one CRL issuer is given.");
                }
                DEREncodable relName = dp.getDistributionPoint().getName();
                Iterator it = issuers.iterator();
                List issuersTemp = new ArrayList(issuers.size());
                while (it.hasNext())
                {
                    Enumeration e = null;
                    try
                    {
                        e = ASN1Sequence.getInstance(
                            new ASN1InputStream(((X500Principal) it.next())
                                .getEncoded()).readObject()).getObjects();
                    }
                    catch (IOException ex)
                    {
                        throw new AnnotatedException(
                            "Cannot decode CRL issuer information.", ex);
                    }
                    ASN1EncodableVector v = new ASN1EncodableVector();
                    while (e.hasMoreElements())
                    {
                        v.add((DEREncodable) e.nextElement());
                    }
                    v.add(relName);
                    issuersTemp.add(new X500Principal(new DERSequence(v)
                        .getDEREncoded()));
                }
                issuers.clear();
                issuers.addAll(issuersTemp);
            }
        }
        Iterator it = issuers.iterator();
        while (it.hasNext())
        {
            try
            {
                selector.addIssuerName(((X500Principal)it.next()).getEncoded());
            }
            catch (IOException ex)
            {
                throw new AnnotatedException(
                    "Cannot decode CRL issuer information.", ex);
            }
        }
    }

    protected static void getCertStatus(Date validDate, X509CRL crl,
        BigInteger serialNumber, CertStatus certStatus)
        throws AnnotatedException
    {
        // (i) or (j)
        // TODO: If two certificates from different issuers in indirect CRLs have
        // the same serial number ...
        X509CRLEntry crl_entry = crl.getRevokedCertificate(serialNumber);
        if (crl_entry != null)
        {
            DEREnumerated reasonCode = null;
            if (crl_entry.hasExtensions())
            {
                try
                {
                    reasonCode = DEREnumerated
                        .getInstance(CertPathValidatorUtilities
                            .getExtensionValue(crl_entry,
                                X509Extensions.ReasonCode.getId()));
                }
                catch (Exception e)
                {
                    new AnnotatedException(
                        "Reason code CRL entry extension could not be decoded.",
                        e);
                }
            }

            // for reason keyCompromise, caCompromise, aACompromise or
            // unspecified
            if (!(validDate.getTime() < crl_entry.getRevocationDate().getTime())
                || reasonCode == null
                || reasonCode.getValue().intValue() == 0
                || reasonCode.getValue().intValue() == 1
                || reasonCode.getValue().intValue() == 2
                || reasonCode.getValue().intValue() == 8)
            {

                // (i) or (j) (1)
                if (reasonCode != null)
                {
                    certStatus.setCertStatus(reasonCode.getValue().intValue());
                }
                // (i) or (j) (2)
                else
                {
                    certStatus.setCertStatus(CRLReason.unspecified);
                }
                certStatus.setRevocationDate(crl_entry.getRevocationDate());
            }
        }
    }

    /**
     * Fetches delta CRLs according to RFC 3280 section 5.2.4.
     *
     * @param currentDate The date for which the delta CRLs must be valid.
     * @param paramsPKIX The extended PKIX parameters.
     * @param completeCRL The complete CRL the delta CRL is for.
     * @return A <code>Set</code> of <code>X509CRL</code>s with delta CRLs.
     * @throws AnnotatedException if an exception occurs while picking the delta
     *             CRLs or no delta CRLs are found.
     */
    protected static Set getDeltaCRLs(Date currentDate,
        ExtendedPKIXParameters paramsPKIX, X509CRL completeCRL)
        throws AnnotatedException
    {

        Set set = new HashSet();

        X509CRLStoreSelector deltaSelect = new X509CRLStoreSelector();
        deltaSelect.setDateAndTime(currentDate);

        // 5.2.4 (a)
        try
        {
            deltaSelect.addIssuerName(CertPathValidatorUtilities
                .getIssuerPrincipal(completeCRL).getEncoded());
        }
        catch (IOException e)
        {
            new AnnotatedException("Cannot extract issuer from CRL.", e);
        }

        BigInteger completeCRLNumber;
        try
        {
            completeCRLNumber = CRLNumber.getInstance(
                CertPathValidatorUtilities.getExtensionValue(completeCRL,
                    CRL_NUMBER)).getPositiveValue();
        }
        catch (Exception e)
        {
            throw new AnnotatedException(
                "CRL number extension could not be extracted from CRL.", e);
        }

        // 5.2.4 (b)
        byte[] idp = null;
        try
        {
            idp = completeCRL.getExtensionValue(ISSUING_DISTRIBUTION_POINT);
        }
        catch (Exception e)
        {
            throw new AnnotatedException(
                "Issuing distribution point extension value could not be read.",
                e);
        }
        deltaSelect.setIssuingDistributionPoint(idp);
        deltaSelect.setIssuingDistributionPointEnabled(true);

        // 5.2.4 (c)
        deltaSelect.setMaxBaseCRLNumber(completeCRLNumber);

        // 5.2.4 (d)

        deltaSelect.setMinCRLNumber(completeCRLNumber
            .add(BigInteger.valueOf(1)));

        Set temp = new HashSet();
        // find delta CRLs
        try
        {
            temp.addAll(CertPathValidatorUtilities.findCRLs(deltaSelect,
                paramsPKIX.getAddionalStores()));
            temp.addAll(CertPathValidatorUtilities.findCRLs(deltaSelect,
                paramsPKIX.getStores()));
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException("Could not search for delta CRLs.", e);
        }
        if (set.isEmpty())
        {
            throw new AnnotatedException("No delta CRLs found.");
        }
        return set;
    }

    /**
     * Fetches complete CRLs according to RFC 3280.
     *
     * @param dp The distribution point for which the complete CRL
     * @param cert The <code>X509Certificate</code> or
     *            {@link org.bouncycastle.x509.X509AttributeCertificate} for
     *            which the CRL should be searched.
     * @param currentDate The date for which the delta CRLs must be valid.
     * @param paramsPKIX The extended PKIX parameters.
     * @return A <code>Set</code> of <code>X509CRL</code>s with complete
     *         CRLs.
     * @throws AnnotatedException if an exception occurs while picking the CRLs
     *             or no CRLs are found.
     */
    protected static Set getCompleteCRLs(DistributionPoint dp, Object cert,
        Date currentDate, ExtendedPKIXParameters paramsPKIX)
        throws AnnotatedException
    {
        X509CRLStoreSelector crlselect = new X509CRLStoreSelector();
        try
        {
            Set issuers = new HashSet();
            if (cert instanceof X509AttributeCertificate)
            {
                issuers.add(((X509AttributeCertificate) cert)
                    .getIssuer().getPrincipals()[0]);
            }
            else
            {
                issuers.add(((X509Certificate)cert).getSubjectX500Principal());
            }
            CertPathValidatorUtilities.getCRLIssuersFromDistributionPoint(dp,
                issuers, crlselect, paramsPKIX);
        }
        catch (AnnotatedException e)
        {
            new AnnotatedException(
                "Could not get issuer information from distribution point.", e);
        }
        if (cert instanceof X509Certificate)
        {
            crlselect.setCertificateChecking((X509Certificate) cert);
        }
        else
        {
            crlselect
                .setAttrCertificateChecking((X509AttributeCertificate) cert);
        }
        crlselect.setDateAndTime(currentDate);
        crlselect.setCompleteCRLEnabled(true);

        Set crls = new HashSet();
        try
        {
            crls.addAll(CertPathValidatorUtilities.findCRLs(crlselect,
                paramsPKIX.getStores()));
            crls.addAll(CertPathValidatorUtilities.findCRLs(crlselect,
                paramsPKIX.getAddionalStores()));
        }
        catch (AnnotatedException e)
        {
            throw new AnnotatedException("Could not search for CRLs.", e);
        }
        if (crls.isEmpty())
        {
            throw new AnnotatedException("No CRLs found.");
        }
        return crls;
    }

    protected static Date getValidCertDateFromValidityModel(
        ExtendedPKIXParameters paramsPKIX, CertPath certPath, int index)
        throws AnnotatedException
    {
        if (paramsPKIX.getValidityModel() == ExtendedPKIXParameters.CHAIN_VALIDITY_MODEL)
        {
            // if end cert use given signing/encryption/... time
            if (index <= 0)
            {
                return CertPathValidatorUtilities.getValidDate(paramsPKIX);
                // else use time when previous cert was created
            }
            else
            {
                if (index - 1 == 0)
                {
                    DERGeneralizedTime dateOfCertgen = null;
                    try
                    {
                        dateOfCertgen = DERGeneralizedTime
                            .getInstance(((X509Certificate) certPath
                                .getCertificates().get(index - 1))
                                .getExtensionValue(ISISMTTObjectIdentifiers.id_isismtt_at_dateOfCertGen
                                    .getId()));
                    }
                    catch (IllegalArgumentException e)
                    {
                        throw new AnnotatedException(
                            "Date of cert gen extension could not be read.");
                    }
                    if (dateOfCertgen != null)
                    {
                        try
                        {
                            return dateOfCertgen.getDate();
                        }
                        catch (ParseException e)
                        {
                            throw new AnnotatedException(
                                "Date from dat of cert gen extension could not be parsed.",
                                e);
                        }
                    }
                    return ((X509Certificate) certPath.getCertificates().get(
                        index - 1)).getNotBefore();
                }
                else
                {
                    return ((X509Certificate) certPath.getCertificates().get(
                        index - 1)).getNotBefore();
                }
            }
        }
        else
        {
            return getValidDate(paramsPKIX);
        }
    }
}
