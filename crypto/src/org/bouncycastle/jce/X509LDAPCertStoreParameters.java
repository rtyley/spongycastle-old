package org.bouncycastle.jce;

import java.security.cert.CertStoreParameters;
import java.util.List;

/**
 * An expanded set of parameters for an LDAPCertStore
 */
public class X509LDAPCertStoreParameters
    implements CertStoreParameters
{

    private String ldapURL;

    private String baseDN = "";

    private List certificateAttributes;

    private List crlAttributes;

    private String ldapCertificateAttributeName;

    private String certificateSubjectAttributeName;

    private String ldapCRLAttributeName;

    private String cRLIssuerAttributeName;

    private String searchForSerialNumberIn;

    /**
     * 
     * @param ldapURL
     *            The LDAP URL. If <code>null</code> "ldap://localhost:389" is
     *            used.
     * @param baseDN
     *            The base DN in the LDAP tree to start searching. Maybe
     *            <code>null</code> and teh whole tree is searched.
     * @param certificateAttributes
     *            Attribute names in the LDAP directory where certificates are
     *            stored.
     * @param crlAttributes
     *            Attribute names in the LDAP directory where CRLs are stored.
     * @param ldapCertificateAttributeName
     *            The attribute name in the LDAP directory where to search for
     *            the attribute value of the specified
     *            <code>certificateSubjectAttributeName</code>.
     * @param certificateSubjectAttributeName
     *            An attribute in the subject of the certificate which is used
     *            to be searched in the
     *            <code>ldapCertificateAttributeName</code>.
     * @param ldapCRLAttributeName
     *            The attribute name in the LDAP directory where to search for
     *            the attribute value of the specified
     *            <code>cRLIssuerAttributeName</code>.
     * @param cRLIssuerAttributeName
     *            An attribute in the issuer of the CRL which is used to be
     *            searched in the <code>ldapCRLAttributeName</code>.
     * @param searchForSerialNumberIn
     *            If not <code>null</code> the serial number of the
     *            certificate is seached in the LDAP attribute.
     * @throws IllegalArgumentException
     *             if a parameter except <code>ldapURL</code> or
     *             <code>searchForSerialNumberIn</code> is <code>null</code>.
     */
    public X509LDAPCertStoreParameters(String ldapURL, String baseDN,
            List certificateAttributes, List crlAttributes,
            String ldapCertificateAttributeName,
            String certificateSubjectAttributeName,
            String ldapCRLAttributeName, String cRLIssuerAttributeName,
            String searchForSerialNumberIn)
    {
        this.ldapURL = ldapURL;
        if (ldapURL == null)
        {
            ldapURL = "ldap://localhost:389";
        }
        if (baseDN != null)
        {
            this.baseDN = baseDN;
        }
        this.certificateAttributes = certificateAttributes;
        this.crlAttributes = crlAttributes;
        this.ldapCertificateAttributeName = ldapCertificateAttributeName;
        this.certificateSubjectAttributeName = certificateSubjectAttributeName;
        this.cRLIssuerAttributeName = cRLIssuerAttributeName;
        this.ldapCRLAttributeName = ldapCRLAttributeName;
        this.searchForSerialNumberIn = searchForSerialNumberIn;
        if (certificateAttributes == null || crlAttributes == null
                || ldapCertificateAttributeName == null
                || certificateSubjectAttributeName == null
                || ldapCRLAttributeName == null
                || cRLIssuerAttributeName == null)
        {
            throw new IllegalArgumentException(
                    "All parameters must be specified.");
        }
    }

    /**
     * Returns the LDAP URL.
     * 
     * @return The LDAP URL.
     */
    public String getLDAPURL()
    {
        return ldapURL;
    }

    /**
     * Returns a clone of this object.
     */
    public Object clone()
    {
        return new X509LDAPCertStoreParameters(ldapURL, baseDN,
                certificateAttributes, crlAttributes,
                ldapCertificateAttributeName, certificateSubjectAttributeName,
                ldapCRLAttributeName, cRLIssuerAttributeName,
                searchForSerialNumberIn);
    }

    /**
     * @return Returns the certificateAttributes.
     */
    public List getCertificateAttributes()
    {
        return certificateAttributes;
    }

    /**
     * @return Returns the crlAttributes.
     */
    public List getCrlAttributes()
    {
        return crlAttributes;
    }

    /**
     * @return Returns the certificateSubjectAttributeName.
     */
    public String getCertificateSubjectAttributeName()
    {
        return certificateSubjectAttributeName;
    }

    /**
     * @return Returns the cRLIssuerAttributeName.
     */
    public String getCRLIssuerAttributeName()
    {
        return cRLIssuerAttributeName;
    }

    /**
     * @return Returns the ldapCertificateAttributeName.
     */
    public String getLdapCertificateAttributeName()
    {
        return ldapCertificateAttributeName;
    }

    /**
     * @return Returns the ldapCRLAttributeName.
     */
    public String getLdapCRLAttributeName()
    {
        return ldapCRLAttributeName;
    }

    /**
     * @return Returns the searchForSerialNumberIn.
     */
    public String getSearchForSerialNumberIn()
    {
        return searchForSerialNumberIn;
    }

    /**
     * @return Returns the baseDN.
     */
    public String getBaseDN()
    {
        return baseDN;
    }
}
