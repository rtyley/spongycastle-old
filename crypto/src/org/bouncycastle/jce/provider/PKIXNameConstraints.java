package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;

import java.security.cert.CertPathValidatorException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class PKIXNameConstraints
{
    private Set permittedSubtreesDN = new HashSet();
    private Set excludedSubtreesDN = new HashSet();
    private Set permittedSubtreesEmail = new HashSet();
    private Set permittedSubtreesIP = new HashSet();
    private Set excludedSubtreesEmail = new HashSet();
    private Set excludedSubtreesIP = new HashSet();

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

    public void checkPermittedDN(ASN1Sequence dns)
        throws CertPathValidatorException
    {
        checkPermittedDN(permittedSubtreesDN, dns);
    }

    public void checkExcludedDN(ASN1Sequence dns)
        throws CertPathValidatorException
    {
        checkPermittedDN(excludedSubtreesDN, dns);
    }

    private void checkPermittedDN(Set permitted, ASN1Sequence dns)
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

    private void checkExcludedDN(Set excluded, ASN1Sequence dns)
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

    private Set intersectDN(Set permitted, ASN1Sequence dn)
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

    private Set unionDN(Set excluded, ASN1Sequence dn)
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

    private Set intersectEmail(Set permitted, String email)
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

    private Set unionEmail(Set excluded, String email)
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

    private Set intersectIP(Set permitted, byte[] ip)
    {
        // TODO
        return permitted;
    }

    private Set unionIP(Set excluded, byte[] ip)
    {
        // TODO
        return excluded;
    }

    private void checkPermittedEmail(Set permitted, String email)
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

    private void checkExcludedEmail(Set excluded, String email)
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

    private void checkPermittedIP(Set permitted, byte[] ip)
            throws CertPathValidatorException
    {
        if (permitted.isEmpty())
        {
            return;
        }

        // TODO: ??? Something here
    }

    private void checkExcludedIP(Set excluded, byte[] ip)
            throws CertPathValidatorException
    {
        if (excluded.isEmpty())
        {
            return;
        }

        // TODO, check RFC791 and RFC1883 for IP bytes definition.
    }


    public void checkPermitted(GeneralName name)
        throws CertPathValidatorException
    {
        switch(name.getTagNo())
        {
        case 1:
            String email = DERIA5String.getInstance(name.getName()).getString();

            checkPermittedEmail(permittedSubtreesEmail, email);
            break;
        case 4:
            checkPermittedDN(ASN1Sequence.getInstance(name.getName()));
            break;
        case 7:
            byte[] ip = ASN1OctetString.getInstance(name.getName()).getOctets();

            checkPermittedIP(permittedSubtreesIP, ip);
        }
    }

    public void checkExcluded(GeneralName name)
        throws CertPathValidatorException
    {
        switch(name.getTagNo())
        {
        case 1:
            String email = DERIA5String.getInstance(name.getName()).getString();

            checkExcludedEmail(excludedSubtreesEmail, email);
            break;
        case 4:
            checkExcludedDN(ASN1Sequence.getInstance(name.getName()));
            break;
        case 7:
            byte[] ip = ASN1OctetString.getInstance(name.getName()).getOctets();

            checkExcludedIP(excludedSubtreesIP, ip);
        }
    }

    public void intersectPermittedSubtree(GeneralSubtree subtree)
    {
        GeneralName     name = subtree.getBase();
        switch(name.getTagNo())
        {
        case 1:
            String email = DERIA5String.getInstance(name.getName()).getString();

            intersectEmail(permittedSubtreesEmail, email);
            break;
        case 4:
            intersectDN(permittedSubtreesDN, ASN1Sequence.getInstance(name.getName()));
            break;
        case 7:
            byte[] ip = ASN1OctetString.getInstance(name.getName()).getOctets();

            intersectIP(permittedSubtreesIP, ip);
        }
    }

    public void addExcludedSubtree(GeneralSubtree subtree)
    {
        GeneralName     base = subtree.getBase();

        switch(base.getTagNo())
        {
        case 1:
            excludedSubtreesEmail = unionEmail(excludedSubtreesEmail, DERIA5String.getInstance(base.getName()).getString());
            break;
        case 4:
            excludedSubtreesDN = unionDN(excludedSubtreesDN, (ASN1Sequence)base.getName());
            break;
        case 7:
            excludedSubtreesIP = unionIP(excludedSubtreesIP, ASN1OctetString.getInstance(base.getName()).getOctets());
            break;
        }
    }
}
