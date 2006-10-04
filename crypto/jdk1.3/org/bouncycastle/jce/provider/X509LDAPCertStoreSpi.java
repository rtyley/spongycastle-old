package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CRL;
import org.bouncycastle.jce.cert.CRLSelector;
import org.bouncycastle.jce.cert.CertSelector;
import org.bouncycastle.jce.cert.CertStoreException;
import org.bouncycastle.jce.cert.CertStoreParameters;
import org.bouncycastle.jce.cert.CertStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import org.bouncycastle.jce.cert.X509CRLSelector;
import org.bouncycastle.jce.cert.X509CertSelector;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;

/**
 * 
 * This is a general purpose implementation to get X.509 certificates and CRLs
 * from a LDAP location.
 */
public class X509LDAPCertStoreSpi
    extends CertStoreSpi
{
    private X509LDAPCertStoreParameters params;

    public X509LDAPCertStoreSpi(CertStoreParameters params)
            throws InvalidAlgorithmParameterException
    {
        super(params);

        if (!(params instanceof X509LDAPCertStoreParameters))
        {
            throw new InvalidAlgorithmParameterException(
                    "org.bouncycastle.jce.provider.LDAPCertStoreSpi: parameter must be a LDAPCertStoreParameters object\n"
                            + params.toString());
        }

        this.params = (X509LDAPCertStoreParameters) params;
    }

    /** Initial Context Factory. */
    private static String LDAP_PROVIDER = "com.sun.jndi.ldap.LdapCtxFactory";

    /** Processing referrals.. */
    private static String REFERRALS_IGNORE = "ignore";

    /** Security level to be used for LDAP connections. */
    private static final String SEARCH_SECURITY_LEVEL = "none";

    /** Package Prefix for loading URL context factories. */
    private static final String URL_CONTEXT_PREFIX = "com.sun.jndi.url";

    private DirContext connectLDAP()
        throws NamingException
    {
        Properties props = new Properties();
        props.setProperty(Context.INITIAL_CONTEXT_FACTORY, LDAP_PROVIDER);
        props.setProperty(Context.BATCHSIZE, "0");

        props.setProperty(Context.PROVIDER_URL, params.getLDAPURL());
        props.setProperty(Context.URL_PKG_PREFIXES, URL_CONTEXT_PREFIX);
        props.setProperty(Context.REFERRAL, REFERRALS_IGNORE);
        props.setProperty(Context.SECURITY_AUTHENTICATION,
                SEARCH_SECURITY_LEVEL);

        DirContext ctx = new InitialDirContext(props);
        return ctx;
    }

    private String parseDN(String subject, String subjectAttributeName)
    {
        String temp = subject;
        int begin = temp.toLowerCase().indexOf(
                subjectAttributeName.toLowerCase());
        temp = temp.substring(begin + subjectAttributeName.length());
        int end = temp.indexOf(',');
        if (end == -1)
        {
            end = temp.length();
        }
        while (temp.charAt(end - 1) == '\\')
        {
            end = temp.indexOf(',', end + 1);
            if (end == -1)
            {
                end = temp.length();
            }
        }
        temp = temp.substring(0, end);
        begin = temp.indexOf('=');
        temp = temp.substring(begin + 1);
        if (temp.charAt(0) == ' ')
        {
            temp = temp.substring(1);
        }
        return temp;
    }

    public Collection engineGetCertificates(CertSelector selector)
            throws CertStoreException
    {
        String[] attrs = (String[]) params.getCertificateAttributes().toArray(
                new String[0]);
        if (!(selector instanceof X509CertSelector))
        {
            throw new CertStoreException("selector is not a X509CertSelector");
        }
        X509CertSelector xselector = (X509CertSelector) selector;
        Set set = null;
        String attrName = params.getLdapCertificateAttributeName();
        try
        {
            if (xselector.getSubjectAsBytes() != null
                    || xselector.getCertificate() != null)
            {
                String subject = null;
                String serial = null;
                if (xselector.getCertificate() != null)
                {
                    subject = xselector.getCertificate().getSubjectDN().getName();
                    serial = xselector.getCertificate().getSerialNumber()
                            .toString();
                }
                else
                {
                    subject = new X509Principal(xselector.getSubjectAsBytes()).getName();
                }
                String subjectAttributeName = params
                        .getCertificateSubjectAttributeName();
                String attrValue = parseDN(subject, subjectAttributeName);
                set = search(attrName, "*" + attrValue + "*", attrs);
                if (serial != null)
                {
                    attrValue = serial;
                    attrName = params.getSearchForSerialNumberIn();
                    set.addAll(search(attrName, "*" + attrValue + "*", attrs));
                }
            }
            else
            {
                set = search(attrName, "*", attrs);
            }
        }
        catch (IOException e)
        {
            throw new CertStoreException(
                    "exception processing selector: " + e);
        }
        Iterator it = set.iterator();
        Set certSet = new HashSet();
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509",
                    "BC");
            while (it.hasNext())
            {
                Certificate cert = cf
                        .generateCertificate(new ByteArrayInputStream(
                                (byte[]) it.next()));
//                System.out.println(((X509Certificate) cert)
//                        .getSubjectX500Principal());
                if (xselector.match(cert))
                {
                    certSet.add(cert);
                }
            }
        }
        catch (Exception e)
        {
            throw new CertStoreException(
                    "certificate cannot be constructed from LDAP result: " + e);
        }
        return certSet;
    }

    public Collection engineGetCRLs(CRLSelector selector)
            throws CertStoreException
    {
        String[] attrs = (String[]) params.getCrlAttributes().toArray(
                new String[0]);
        if (!(selector instanceof X509CRLSelector))
        {
            throw new CertStoreException("selector is not a X509CRLSelector");
        }
        X509CRLSelector xselector = (X509CRLSelector) selector;
        Set set = null;
        String attrName = params.getLdapCRLAttributeName();
        if (xselector.getIssuerNames() != null)
        {
            for (Iterator it = xselector.getIssuerNames().iterator(); it.hasNext();)
            {
                String issuer = ((String)it.next());
                String issuerAttributeName = params.getCRLIssuerAttributeName();
                String attrValue = parseDN(issuer, issuerAttributeName);
                set = search(attrName, attrValue + "*", attrs);
            }
        }
        else if (xselector.getIssuerNames() != null)
        {
            for (Iterator it = xselector.getIssuerNames().iterator(); it
                    .hasNext();)
            {
                Object o = it.next();
                String attrValue = null;
                try
                {
                    if (o instanceof String)
                    {
                        String issuerAttributeName = params
                                .getCRLIssuerAttributeName();
                        attrValue = parseDN((String) o, issuerAttributeName);
                    }
                    else
                    {
                        String issuerAttributeName = params
                                .getCRLIssuerAttributeName();
                        attrValue = parseDN(
                                new X509Principal((byte[]) o).getName(),
                                issuerAttributeName);
                    }
                }
                catch (IOException e)
                {
                    throw new CertStoreException(
                        "exception setting attrValue: " + e);
                }
                set = search(attrName, "*" + attrValue + "*", attrs);
            }
        }
        else
        {
            set = search(attrName, "*", attrs);
        }
        Iterator it = set.iterator();
        Set crlSet = new HashSet();
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509",
                    "BC");
            while (it.hasNext())
            {
                CRL crl = cf.generateCRL(new ByteArrayInputStream((byte[]) it
                        .next()));
                if (xselector.match(crl))
                {
                    crlSet.add(crl);
                }
            }
        }
        catch (Exception e)
        {
            throw new CertStoreException(
                    "CRL cannot be constructed from LDAP result " + e);
        }
        return crlSet;
    }

    /**
     * Returns a Set of byte arrays with the certificate or CRL encodings.
     * 
     * @param attributeName
     *            The attribute name to look for in the LDAP.
     * @param attributeValue
     *            The value the attribute name must have.
     * @param attrs
     *            The attributes in the LDAP which hold the certificate or CRL
     *            in a found entry.
     * @return Set of byte arrays with the certificate encodings.
     */
    private Set search(String attributeName, String attributeValue,
            String[] attrs) throws CertStoreException
    {
        String filter = attributeName + "=" + attributeValue;
        DirContext ctx = null;
        Set set = new HashSet();
        try
        {

            ctx = connectLDAP();

            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setCountLimit(0);
            for (int i = 0; i < attrs.length; i++)
            {
                String temp[] = new String[1];
                temp[0] = attrs[i];
                constraints.setReturningAttributes(temp);

                String filter2 = "(&("+filter+")("+temp[0]+"=*))";
                NamingEnumeration results = ctx.search(params.getBaseDN(), filter2,
                        constraints);
                while (results.hasMoreElements())
                {
                    SearchResult sr = (SearchResult) results.next();
                    // should only be one attribute in the attribute set with
                    // one
                    // attribute value as byte array
                    if (sr.getAttributes().getAll().hasMore())
                    {
                        set.add(((Attribute) (sr.getAttributes().getAll()
                                .next())).getAll().next());
                    }
                }
            }
        }
        catch (Exception e)
        {
            throw new CertStoreException(
                    "Error getting results from LDAP directory " + e);

        }
        finally
        {
            try
            {
                if (null != ctx)
                {
                    ctx.close();
                }
            }
            catch (Exception e)
            {
            }
        }
        return set;
    }

}
