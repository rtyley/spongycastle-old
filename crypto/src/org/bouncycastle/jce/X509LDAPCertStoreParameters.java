package org.bouncycastle.jce;

import java.security.cert.CertStoreParameters;

/**
 * An expanded set of parameters for an LDAPCertStore
 */
public class X509LDAPCertStoreParameters implements CertStoreParameters
{

    private String ldapURL;

    private String baseDN;

    private String certificateAttribute;

    private String cACertificateAttribute;

    private String crossCertificateAttribute;

    private String crlAttribute;

    private String ldapCertificateAttributeName;

    private String certificateSubjectAttributeName;

    private String ldapCACertificateAttributeName;

    private String cACertificateSubjectAttributeName;

    private String ldapCrossCertificateAttributeName;

    private String crossCertificateSubjectAttributeName;

    private String ldapCRLAttributeName;

    private String cRLIssuerAttributeName;

    private String searchForSerialNumberIn;

    /**
     * @param ldapURL                        The LDAP URL. If <code>null</code> "ldap://localhost:389" is
     *                                       used.
     * @param baseDN                         The base DN in the LDAP tree to start searching. May be
     *                                       <code>null</code> and the whole tree is searched.
     * @param certificateAttribute           Attribute name in the LDAP directory where end certificates
     *                                       are stored. Defaults to userCertificate if <code>null</code>.
     * @param cACertificateAttribute         Attribute name in the LDAP directory where CA certificates are
     *                                       stored. Defaults to cACertificate if <code>null</code>.
     * @param crossCertificateAttribute      Attribute name, where the cross certificates are stored.
     *                                       Defaults to crossCertificatePair if <code>null</code>
     * @param crlAttribute                   Attribute names in the LDAP directory where CRLs are stored.
     *                                       Defaults to certificateRevocationList if <code>null</code>.
     * @param ldapCertificateAttributeName   The attribute name in the LDAP directory where to search for
     *                                       the attribute value of the specified
     *                                       <code>certificateSubjectAttributeName</code>. E.g. if "cn"
     *                                       is used to put information about the subject for end
     *                                       certificates, then specify "cn".
     * @param certificateSubjectAttributeName
     *                                       An attribute in the subject of the certificate which is used
     *                                       to be searched in the
     *                                       <code>ldapCertificateAttributeName</code>. E.g. the "cn"
     *                                       attribute of the DN could be used.
     * @param ldapCACertificateAttributeName The attribute name in the LDAP directory where to search for
     *                                       the attribute value of the specified
     *                                       <code>cACertificateSubjectAttributeName</code>. E.g. if
     *                                       "ou" is used to put information about the subject for CA
     *                                       certificates, then specify "ou".
     * @param cACertificateSubjectAttributeName
     *                                       An attribute in the subject of the certificate which is used
     *                                       to be searched in the
     *                                       <code>ldapCACertificateAttributeName</code>. E.g. the "ou"
     *                                       attribute of the DN may be appropriate.
     * @param ldapCrossCertificateAttributeName
     *                                       The attribute name in the LDAP directory where to search for
     *                                       the attribute value of the specified
     *                                       <code>crossCertificateSubjectAttributeName</code>. E.g. if
     *                                       "o" is used to put information about the subject for cross
     *                                       certificates, then specify "o".
     * @param crossCertificateSubjectAttributeName
     *                                       An attribute in the subject of the cross certificate which is
     *                                       used to be searched in the
     *                                       <code>ldapCrossCertificateAttributeName</code>. E.g. the
     *                                       "o" attribute of the DN may be appropriate.
     * @param ldapCRLAttributeName           The attribute name in the LDAP directory where to search for
     *                                       the attribute value of the specified
     *                                       <code>cRLIssuerAttributeName</code>. E.g. if "ou" is used
     *                                       to put information about the issuer of CRLs, specify "ou" .
     * @param cRLIssuerAttributeName         An attribute in the issuer of the CRL which is used to be
     *                                       searched in the <code>ldapCRLAttributeName</code>. E.g. the
     *                                       "o" or "ou" attribute may be used.
     * @param searchForSerialNumberIn        If not <code>null</code> the serial number of the
     *                                       certificate is searched in this LDAP attribute.
     * @throws IllegalArgumentException if a necessary parameter is <code>null</code>.
     */
    public X509LDAPCertStoreParameters(String ldapURL, String baseDN,
                                       String certificateAttribute, String cACertificateAttribute,
                                       String crossCertificateAttribute, String crlAttribute,
                                       String ldapCertificateAttributeName,
                                       String certificateSubjectAttributeName,
                                       String ldapCACertificateAttributeName,
                                       String cACertificateSubjectAttributeName,
                                       String ldapCrossCertificateAttributeName,
                                       String crossCertificateSubjectAttributeName,
                                       String ldapCRLAttributeName, String cRLIssuerAttributeName,
                                       String searchForSerialNumberIn)
    {
        this(ldapURL, baseDN, ldapCertificateAttributeName,
            certificateSubjectAttributeName,
            ldapCACertificateAttributeName,
            cACertificateSubjectAttributeName,
            ldapCrossCertificateAttributeName,
            crossCertificateSubjectAttributeName, ldapCRLAttributeName,

            cRLIssuerAttributeName, searchForSerialNumberIn);
        this.certificateAttribute = certificateAttribute;
        this.crossCertificateAttribute = crossCertificateAttribute;
        this.cACertificateAttribute = cACertificateAttribute;
        this.crlAttribute = crlAttribute;
    }

    /**
     * @param ldapURL                        The LDAP URL. If <code>null</code> "ldap://localhost:389" is
     *                                       used.
     * @param baseDN                         The base DN in the LDAP tree to start searching. May be
     *                                       <code>null</code> and the whole tree is searched.
     * @param ldapCertificateAttributeName   The attribute name in the LDAP directory where to search for
     *                                       the attribute value of the specified
     *                                       <code>certificateSubjectAttributeName</code>. E.g. if "cn"
     *                                       is used to put information about the subject for end
     *                                       certificates, then specify "cn".
     * @param certificateSubjectAttributeName
     *                                       An attribute in the subject of the certificate which is used
     *                                       to be searched in the
     *                                       <code>ldapCertificateAttributeName</code>. E.g. the "cn"
     *                                       attribute of the DN could be used.
     * @param ldapCACertificateAttributeName The attribute name in the LDAP directory where to search for
     *                                       the attribute value of the specified
     *                                       <code>cACertificateSubjectAttributeName</code>. E.g. if
     *                                       "ou" is used to put information about the subject for CA
     *                                       certificates, then specify "ou".
     * @param cACertificateSubjectAttributeName
     *                                       An attribute in the subject of the certificate which is used
     *                                       to be searched in the
     *                                       <code>ldapCACertificateAttributeName</code>. E.g. the "ou"
     *                                       attribute of the DN may be appropriate.
     * @param ldapCrossCertificateAttributeName
     *                                       The attribute name in the LDAP directory where to search for
     *                                       the attribute value of the specified
     *                                       <code>crossCertificateSubjectAttributeName</code>. E.g. if
     *                                       "o" is used to put information about the subject for cross
     *                                       certificates, then specify "o".
     * @param crossCertificateSubjectAttributeName
     *                                       An attribute in the subject of the cross certificate which is
     *                                       used to be searched in the
     *                                       <code>ldapCrossCertificateAttributeName</code>. E.g. the
     *                                       "o" attribute of the DN may be appropriate.
     * @param ldapCRLAttributeName           The attribute name in the LDAP directory where to search for
     *                                       the attribute value of the specified
     *                                       <code>cRLIssuerAttributeName</code>. E.g. if "ou" is used
     *                                       to put information about the issuer of CRLs, specify "ou" .
     * @param cRLIssuerAttributeName         An attribute in the issuer of the CRL which is used to be
     *                                       searched in the <code>ldapCRLAttributeName</code>. E.g. the
     *                                       "o" or "ou" attribute may be used.
     * @param searchForSerialNumberIn        If not <code>null</code> the serial number of the
     *                                       certificate is searched in this LDAP attribute.
     * @throws IllegalArgumentException if a necessary parameter is <code>null</code>.
     */
    public X509LDAPCertStoreParameters(String ldapURL, String baseDN,

                                       String ldapCertificateAttributeName,
                                       String certificateSubjectAttributeName,
                                       String ldapCACertificateAttributeName,
                                       String cACertificateSubjectAttributeName,
                                       String ldapCrossCertificateAttributeName,
                                       String crossCertificateSubjectAttributeName,
                                       String ldapCRLAttributeName, String cRLIssuerAttributeName,
                                       String searchForSerialNumberIn)
    {
        this.ldapURL = ldapURL;
        this.baseDN = baseDN;
        this.ldapCertificateAttributeName = ldapCertificateAttributeName;
        this.certificateSubjectAttributeName = certificateSubjectAttributeName;
        this.ldapCACertificateAttributeName = ldapCACertificateAttributeName;
        this.cACertificateSubjectAttributeName = cACertificateSubjectAttributeName;
        this.ldapCrossCertificateAttributeName = ldapCrossCertificateAttributeName;
        this.crossCertificateSubjectAttributeName = crossCertificateSubjectAttributeName;
        this.cRLIssuerAttributeName = cRLIssuerAttributeName;
        this.ldapCRLAttributeName = ldapCRLAttributeName;
        this.searchForSerialNumberIn = searchForSerialNumberIn;
        if (ldapCertificateAttributeName == null
            || certificateSubjectAttributeName == null
            || ldapCRLAttributeName == null
            || cRLIssuerAttributeName == null
            || ldapCACertificateAttributeName == null
            || cACertificateSubjectAttributeName == null
            || ldapCrossCertificateAttributeName == null
            || crossCertificateSubjectAttributeName == null)
        {
            throw new IllegalArgumentException(
                "Necessary parameters not specified.");
        }

    }

    /**
     * Returns a clone of this object.
     */
    public Object clone()
    {
        return new X509LDAPCertStoreParameters(ldapURL, baseDN,
            certificateAttribute, cACertificateAttribute,
            crossCertificateAttribute, crlAttribute,
            ldapCertificateAttributeName, certificateSubjectAttributeName,
            ldapCACertificateAttributeName,
            cACertificateSubjectAttributeName,
            ldapCrossCertificateAttributeName,
            crossCertificateSubjectAttributeName, ldapCRLAttributeName,
            cRLIssuerAttributeName, searchForSerialNumberIn);
    }

    /**
     * @return Returns the certificateAttribute.
     */
    public String getCertificateAttribute()
    {
        if (certificateAttribute == null)
        {
            certificateAttribute = "userCertificate";
        }
        return certificateAttribute;
    }

    /**
     * @return Returns the crlAttribute.
     */
    public String getCrlAttribute()
    {
        if (crlAttribute == null)
        {
            crlAttribute = "certificateRevocationList";
        }

        return crlAttribute;
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
     * @return Returns the ldapCRLAttributeNames.
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
        if (baseDN == null)
        {
            baseDN = "";
        }
        return baseDN;
    }

    /**
     * @return Returns the crossCertificateAttribute.
     */
    public String getCrossCertificateAttribute()
    {
        if (crossCertificateAttribute == null)
        {
            crossCertificateAttribute = "crossCertificatePair";
        }
        return crossCertificateAttribute;
    }

    /**
     * @return Returns the cACertificateAttribute.
     */
    public String getCACertificateAttribute()
    {
        if (cACertificateAttribute == null)
        {
            cACertificateAttribute = "cACertificate";
        }
        return cACertificateAttribute;
    }

    /**
     * @return Returns the cACertificateSubjectAttributeName.
     */
    public String getCACertificateSubjectAttributeName()
    {
        return cACertificateSubjectAttributeName;
    }

    /**
     * @return Returns the crossCertificateSubjectAttributeName.
     */
    public String getCrossCertificateSubjectAttributeName()
    {
        return crossCertificateSubjectAttributeName;
    }

    /**
     * @return Returns the ldapCACertificateAttributeName.
     */
    public String getLdapCACertificateAttributeName()
    {
        return ldapCACertificateAttributeName;
    }

    /**
     * @return Returns the ldapCrossCertificateAttributeName.
     */
    public String getLdapCrossCertificateAttributeName()
    {
        return ldapCrossCertificateAttributeName;
    }

    /**
     * @return Returns the ldapURL.
     */
    public String getLdapURL()
    {
        if (ldapURL == null)
        {
            ldapURL = "ldap://localhost:389";
        }
        return ldapURL;
	}
}
