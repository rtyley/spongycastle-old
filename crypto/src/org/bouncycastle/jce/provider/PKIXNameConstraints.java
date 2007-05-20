package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import java.security.cert.CertPathValidatorException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class PKIXNameConstraints
{
    private Set excludedSubtreesDN = new HashSet();
    private Set excludedSubtreesDNS = new HashSet();
    private Set excludedSubtreesEmail = new HashSet();
    private Set excludedSubtreesURI = new HashSet();
    private Set excludedSubtreesIP = new HashSet();

    private Set permittedSubtreesDN = new HashSet();
    private Set permittedSubtreesDNS = new HashSet();
    private Set permittedSubtreesEmail = new HashSet();
    private Set permittedSubtreesURI = new HashSet();
    private Set permittedSubtreesIP = new HashSet();

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
        checkExcludedDN(excludedSubtreesDN, dns);
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
        Set intersect = new HashSet();
        if (permitted.isEmpty())
        {
            intersect.add(ip);

            return intersect;
        }
        else
        {
            Iterator _iter = permitted.iterator();
            while (_iter.hasNext())
            {
                byte[] _permitted = (byte[])_iter.next();
                intersect.addAll(intersectIPRange(_permitted, ip));
            }

            return intersect;
        }
    }

    private Set unionIP(Set excluded, byte[] ip)
    {
        if (excluded.isEmpty())
        {
            excluded.add(ip);

            return excluded;
        }
        else
        {
            Set union = new HashSet();

            Iterator _iter = excluded.iterator();
            while (_iter.hasNext())
            {
                byte[] _excluded = (byte[]) _iter.next();
                union.addAll(unionIPRange(_excluded, ip));
            }

            return union;
        }
    }

    private Set unionIPRange(
        byte[] ipWithSubmask1,
        byte[] ipWithSubmask2)
    {
        Set set = new HashSet();

        // difficult, adding always all IPs is not wrong
        if (Arrays.areEqual(ipWithSubmask1, ipWithSubmask2))
        {
            set.add(ipWithSubmask1);
        }
        else
        {
            set.add(ipWithSubmask1);
            set.add(ipWithSubmask2);
        }
        return set;
    }

    private Set intersectIPRange(byte[] ipWithSubmask1,
        byte[] ipWithSubmask2)
    {
        if (ipWithSubmask1.length != ipWithSubmask2.length)
        {
            return Collections.EMPTY_SET;
        }
        byte[][] temp = extractIPsAndSubnetMasks(ipWithSubmask1, ipWithSubmask2);
        byte ip1[] = temp[0];
        byte subnetmask1[] = temp[1];
        byte ip2[] = temp[2];
        byte subnetmask2[] = temp[3];

        byte minMax[][] = minMaxIPs(ip1, subnetmask1, ip2, subnetmask2);
        byte[] min;
        byte[] max;
        max = min(minMax[1], minMax[3]);
        min = max(minMax[0], minMax[2]);

        if (compareTo(min, max) == 1)
        {
            return Collections.EMPTY_SET;
        }
        byte[] ip = or(minMax[0], minMax[2]);
        byte[] subnetmask = or(subnetmask1, subnetmask2);
        return Collections.singleton(ipWithSubnetMask(ip, subnetmask));
    }

    private byte[] ipWithSubnetMask(byte[] ip, byte[] subnetMask)
    {
        int ipLength = ip.length;
        byte[] temp = new byte[ipLength * 2];
        System.arraycopy(ip, 0, temp, 0, ipLength);
        System.arraycopy(subnetMask, 0, temp, ipLength, ipLength);
        return temp;
    }

    private byte[][] extractIPsAndSubnetMasks(
        byte[] ipWithSubmask1,
        byte[] ipWithSubmask2)
    {
        int ipLength = ipWithSubmask1.length / 2;
        byte ip1[] = new byte[ipLength];
        byte subnetmask1[] = new byte[ipLength];
        System.arraycopy(ipWithSubmask1, 0, ip1, 0, ipLength);
        System.arraycopy(ipWithSubmask1, ipLength, subnetmask1, 0, ipLength);

        byte ip2[] = new byte[ipLength];
        byte subnetmask2[] = new byte[ipLength];
        System.arraycopy(ipWithSubmask2, 0, ip2, 0, ipLength);
        System.arraycopy(ipWithSubmask2, ipLength, subnetmask2, 0, ipLength);
        return new byte[][]
        { ip1, subnetmask1, ip2, subnetmask2 };
    }

    private byte[][] minMaxIPs(
        byte[] ip1, byte[] subnetmask1,
        byte[] ip2, byte[] subnetmask2)
    {
        int ipLength = ip1.length;
        byte[] min1 = new byte[ipLength];
        byte[] max1 = new byte[ipLength];

        byte[] min2 = new byte[ipLength];
        byte[] max2 = new byte[ipLength];

        for (int i = 0; i < ipLength; i++)
        {
            min1[i] = (byte) (ip1[i] & subnetmask1[i]);
            max1[i] = (byte) (ip1[i] & subnetmask1[i] | ~subnetmask1[i]);

            min2[i] = (byte) (ip2[i] & subnetmask2[i]);
            max2[i] = (byte) (ip2[i] & subnetmask2[i] | ~subnetmask2[i]);
        }

        return new byte[][] { min1, max1, min2, max2 };
    }


    private void checkPermittedEmail(Set permitted, String email)
            throws CertPathValidatorException
    {
        if (permitted.isEmpty())
        {
            return;
        }

        Iterator it = permitted.iterator();

        while (it.hasNext())
        {
            String str = ((String) it.next());

            if (emailIsConstrained(email, str))
            {
                return;
            }
        }
        
        if (email.length() == 0 && permitted.size() == 0)
        {
            return;
        }

        throw new CertPathValidatorException(
            "Subject email address is not from a permitted subtree.");
    }

    private void checkExcludedEmail(Set excluded, String email)
            throws CertPathValidatorException
    {
        if (excluded.isEmpty())
        {
            return;
        }

        Iterator it = excluded.iterator();

        while (it.hasNext())
        {
            String str = (String) it.next();

            if (emailIsConstrained(email, str))
            {
                throw new CertPathValidatorException(
                    "Email address is from an excluded subtree.");
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

        Iterator it = permitted.iterator();

        while (it.hasNext())
        {
            byte[] ipWithSubnet = (byte[])it.next();

            if (isIPConstrained(ip, ipWithSubnet))
            {
                return;
            }
        }
        if (ip.length == 0 && permitted.size() == 0)
        {
            return;
        }
        throw new CertPathValidatorException(
            "IP is not from a permitted subtree.");
    }

    private void checkExcludedIP(Set excluded, byte[] ip)
            throws CertPathValidatorException
    {
        if (excluded.isEmpty())
        {
            return;
        }

        Iterator it = excluded.iterator();

        while (it.hasNext())
        {
            byte[] ipWithSubnet = (byte[]) it.next();

            if (isIPConstrained(ip, ipWithSubnet))
            {
                throw new CertPathValidatorException(
                    "IP is from an excluded subtree.");
            }
        }
    }

    private boolean isIPConstrained(byte ip[], byte[] constraint)
    {
        int ipLength = ip.length;

        if (ipLength != (constraint.length / 2))
        {
            return false;
        }

        byte[] subnetMask = new byte[ipLength];
        System.arraycopy(constraint, ipLength, subnetMask, 0, ipLength);

        byte[] permittedSubnetAddress = new byte[ipLength];

        byte[] ipSubnetAddress = new byte[ipLength];

        for (int i = 0; i < ipLength; i++)
        {
            permittedSubnetAddress[i] = (byte)(constraint[i] & subnetMask[i]);
            ipSubnetAddress[i] = (byte)(ip[i] & subnetMask[i]);
        }

        return Arrays.areEqual(permittedSubnetAddress, ipSubnetAddress);
    }

    private boolean emailIsConstrained(String email, String constraint)
    {
        String sub = email.substring(email.indexOf('@') + 1);
        // a particular mailbox
        if (constraint.indexOf('@') != -1)
        {
            if (email.equalsIgnoreCase(constraint))
            {
                return true;
            }
        }
        // on particular host
        else if (!(constraint.charAt(0) == '.'))
        {
            if (sub.equalsIgnoreCase(constraint))
            {
                return true;
            }
        }
        // address in sub domain
        else if (withinDomain(sub, constraint))
        {
            return true;
        }
        return false;
    }

    private boolean withinDomain(String testDomain, String domain)
    {
        String tempDomain = domain;
        if (tempDomain.startsWith("."))
        {
            tempDomain = tempDomain.substring(1);
        }
        String[] domainParts = Strings.split(tempDomain, ".");
        String[] testDomainParts = Strings.split(testDomain, ".");
        // must have at least one subdomain
        if (testDomainParts.length <= domainParts.length)
        {
            return false;
        }
        int d = testDomainParts.length - domainParts.length;
        for (int i = -1; i < domainParts.length; i++)
        {
            if (i == -1)
            {
                if (testDomainParts[i + d].equals(""))
                {
                    return false;
                }
            }
            else if (!domainParts[i].equalsIgnoreCase(testDomainParts[i + d]))
            {
                return false;
            }
        }
        return true;
    }

    private void checkPermittedDNS(Set permitted, String dns)
        throws CertPathValidatorException
    {
        if (permitted.isEmpty())
        {
            return;
        }

        Iterator it = permitted.iterator();

        while (it.hasNext())
        {
            String str = ((String) it.next());

            // is sub domain
            if (withinDomain(dns, str) || dns.equalsIgnoreCase(str))
            {
                return;
            }
        }
        if (dns.length() == 0 && permitted.size() == 0)
        {
            return;
        }
        throw new CertPathValidatorException(
            "DNS is not from a permitted subtree.");
    }

    private void checkExcludedDNS(Set excluded, String dns)
        throws CertPathValidatorException
    {
        if (excluded.isEmpty())
        {
            return;
        }

        Iterator it = excluded.iterator();

        while (it.hasNext())
        {
            String str = ((String) it.next());

            // is sub domain or the same
            if (withinDomain(dns, str) || dns.equalsIgnoreCase(str))
            {
                throw new CertPathValidatorException(
                    "DNS is from an excluded subtree.");
            }
        }
    }

   /**
    * The common part of <code>email1</code> and <code>email2</code> is
    * added to the union <code>union</code>. If <code>email1</code> and
    * <code>email2</code> have nothing in common they are added both.
    * 
    * @param email1 Email address constraint 1.
    * @param email2 Email address constraint 2.
    * @param union The union.
    */
   private void unionEmail(String email1, String email2, Set union)
   {
      // email1 is a particular address
      if (email1.indexOf('@') != -1)
      {
         String _sub = email1.substring(email1.indexOf('@') + 1);
         // both are a particular mailbox
         if (email2.indexOf('@') != -1)
         {
            if (email1.equalsIgnoreCase(email2))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a domain
         else if (email2.startsWith("."))
         {
            if (withinDomain(_sub, email2))
            {
               union.add(email2);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a particular host
         else
         {
            if (_sub.equalsIgnoreCase(email2))
            {
               union.add(email2);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
      }
      // email1 specifies a domain
      else if (email1.startsWith("."))
      {
         if (email2.indexOf('@') != -1)
         {
            String _sub = email2.substring(email1.indexOf('@') + 1);
            if (withinDomain(_sub, email1))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a domain
         else if (email2.startsWith("."))
         {
            if (withinDomain(email1, email2)
               || email1.equalsIgnoreCase(email2))
            {
               union.add(email2);
            }
            else if (withinDomain(email2, email1))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         else
         {
            if (withinDomain(email2, email1))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
      }
      // email specifies a host
      else
      {
         if (email2.indexOf('@') != -1)
         {
            String _sub = email2.substring(email1.indexOf('@') + 1);
            if (_sub.equalsIgnoreCase(email1))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a domain
         else if (email2.startsWith("."))
         {
            if (withinDomain(email1, email2))
            {
               union.add(email2);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a particular host
         else
         {
            if (email1.equalsIgnoreCase(email2))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
      }
   }

   private void unionURI(String email1, String email2, Set union)
   {
      // email1 is a particular address
      if (email1.indexOf('@') != -1)
      {
         String _sub = email1.substring(email1.indexOf('@') + 1);
         // both are a particular mailbox
         if (email2.indexOf('@') != -1)
         {
            if (email1.equalsIgnoreCase(email2))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a domain
         else if (email2.startsWith("."))
         {
            if (withinDomain(_sub, email2))
            {
               union.add(email2);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a particular host
         else
         {
            if (_sub.equalsIgnoreCase(email2))
            {
               union.add(email2);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
      }
      // email1 specifies a domain
      else if (email1.startsWith("."))
      {
         if (email2.indexOf('@') != -1)
         {
            String _sub = email2.substring(email1.indexOf('@') + 1);
            if (withinDomain(_sub, email1))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a domain
         else if (email2.startsWith("."))
         {
            if (withinDomain(email1, email2)
               || email1.equalsIgnoreCase(email2))
            {
               union.add(email2);
            }
            else if (withinDomain(email2, email1))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         else
         {
            if (withinDomain(email2, email1))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
      }
      // email specifies a host
      else
      {
         if (email2.indexOf('@') != -1)
         {
            String _sub = email2.substring(email1.indexOf('@') + 1);
            if (_sub.equalsIgnoreCase(email1))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a domain
         else if (email2.startsWith("."))
         {
            if (withinDomain(email1, email2))
            {
               union.add(email2);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
         // email2 specifies a particular host
         else
         {
            if (email1.equalsIgnoreCase(email2))
            {
               union.add(email1);
            }
            else
            {
               union.add(email1);
               union.add(email2);
            }
         }
      }
   }

   private Set intersectDNS(Set permitted, String dns)
   {
      Set intersect = new HashSet();
      if (permitted.isEmpty())
      {
         intersect.add(dns);

         return intersect;
      }
      else
      {
         Iterator _iter = permitted.iterator();
         while (_iter.hasNext())
         {
            String _permitted = (String) _iter.next();

            if (withinDomain(_permitted, dns))
            {
               intersect.add(_permitted);
            }
            else if (withinDomain(dns, _permitted))
            {
               intersect.add(dns);
            }
         }

         return intersect;
      }
   }

   protected Set unionDNS(Set excluded, String dns)
   {
      if (excluded.isEmpty())
      {
         excluded.add(dns);

         return excluded;
      }
      else
      {
         Set union = new HashSet();

         Iterator _iter = excluded.iterator();
         while (_iter.hasNext())
         {
            String _permitted = (String) _iter.next();

            if (withinDomain(_permitted, dns))
            {
               union.add(dns);
            }
            else if (withinDomain(dns, _permitted))
            {
               union.add(_permitted);
            }
            else
            {
               union.add(_permitted);
               union.add(dns);
            }
         }

         return union;
      }
   }

    /**
     * The greatest common part <code>email1</code> and <code>email2</code>
     * is added to the intersection <code>intersect</code>.
     * 
     * @param email1 Email address constraint 1.
     * @param email2 Email address constraint 2.
     * @param intersect The intersection.
     */
    private void intersectEmail(
        String email1,
        String email2,
        Set intersect)
    {
        // email1 is a particular address
        if (email1.indexOf('@') != -1)
        {
            String _sub = email1.substring(email1.indexOf('@') + 1);
            // both are a particular mailbox
            if (email2.indexOf('@') != -1)
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(_sub, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
        // email specifies a domain
        else if (email1.startsWith("."))
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email1.indexOf('@') + 1);
                if (withinDomain(_sub, email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(email1, email2)
                    || email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
                else if (withinDomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
            else
            {
                if (withinDomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
        }
        // email1 specifies a host
        else
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (_sub.equalsIgnoreCase(email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(email1, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
    }

    private void checkExcludedURI(Set excluded, String uri)
        throws CertPathValidatorException
    {
        if (excluded.isEmpty())
        {
            return;
        }

        Iterator it = excluded.iterator();

        while (it.hasNext())
        {
            String str = ((String)it.next());

            if (isUriConstrained(uri, str))
            {
                throw new CertPathValidatorException(
                    "URI is from an excluded subtree.");
            }
        }
    }

    private Set intersectURI(Set permitted, String uri)
    {
        Set intersect = new HashSet();
        if (permitted.isEmpty())
        {
            intersect.add(uri);

            return intersect;
        }
        else
        {
            Iterator _iter = permitted.iterator();
            while (_iter.hasNext())
            {
                String _permitted = (String)_iter.next();
                intersectURI(_permitted, uri, intersect);
            }

            return intersect;
        }
    }

    private Set unionURI(Set excluded, String uri)
    {
        if (excluded.isEmpty())
        {
            excluded.add(uri);

            return excluded;
        }
        else
        {
            Set union = new HashSet();

            Iterator _iter = excluded.iterator();
            while (_iter.hasNext())
            {
                String _excluded = (String)_iter.next();

                unionURI(_excluded, uri, union);
            }

            return union;
        }
    }

    private void intersectURI(
        String email1,
        String email2,
        Set intersect)
    {
        // email1 is a particular address
        if (email1.indexOf('@') != -1)
        {
            String _sub = email1.substring(email1.indexOf('@') + 1);
            // both are a particular mailbox
            if (email2.indexOf('@') != -1)
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(_sub, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (_sub.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
        // email specifies a domain
        else if (email1.startsWith("."))
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email1.indexOf('@') + 1);
                if (withinDomain(_sub, email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(email1, email2)
                    || email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
                else if (withinDomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
            else
            {
                if (withinDomain(email2, email1))
                {
                    intersect.add(email2);
                }
            }
        }
        // email1 specifies a host
        else
        {
            if (email2.indexOf('@') != -1)
            {
                String _sub = email2.substring(email2.indexOf('@') + 1);
                if (_sub.equalsIgnoreCase(email1))
                {
                    intersect.add(email2);
                }
            }
            // email2 specifies a domain
            else if (email2.startsWith("."))
            {
                if (withinDomain(email1, email2))
                {
                    intersect.add(email1);
                }
            }
            // email2 specifies a particular host
            else
            {
                if (email1.equalsIgnoreCase(email2))
                {
                    intersect.add(email1);
                }
            }
        }
    }

    private void checkPermittedURI(Set permitted, String uri)
        throws CertPathValidatorException
    {
        if (permitted == null)
        {
            return;
        }

        Iterator it = permitted.iterator();

        while (it.hasNext())
        {
            String str = ((String)it.next());

            if (isUriConstrained(uri, str))
            {
                return;
            }
        }
        if (uri.length() == 0 && permitted.size() == 0)
        {
            return;
        }
        throw new CertPathValidatorException(
            "URI is not from a permitted subtree.");
    }

    private boolean isUriConstrained(String uri, String constraint)
    {
        String host = extractHostFromURL(uri);
        // a host
        if (!constraint.startsWith("."))
        {
                if (host.equalsIgnoreCase(constraint))
                {
                        return true;
                }
        }

        // in sub domain or domain
        else if (withinDomain(host, constraint))
        {
                return true;
        }

        return false;
    }

    private static String extractHostFromURL(String url)
    {
        // see RFC 1738
        // remove ':' after protocol, e.g. http:
        String sub = url.substring(url.indexOf(':') + 1);
        // extract host from Common Internet Scheme Syntax, e.g. http://
        if (sub.indexOf("//") != -1)
        {
            sub = sub.substring(sub.indexOf("//") + 2);
        }
        // first remove port, e.g. http://test.com:21
        if (sub.lastIndexOf(':') != -1)
        {
            sub = sub.substring(0, sub.lastIndexOf(':'));
        }
        // remove user and password, e.g. http://john:password@test.com
        sub = sub.substring(sub.indexOf(':') + 1);
        sub = sub.substring(sub.indexOf('@') + 1);
        // remove local parts, e.g. http://test.com/bla
        if (sub.indexOf('/') != -1)
        {
            sub = sub.substring(0, sub.indexOf('/'));
        }
        return sub;
    }

    public void checkPermitted(GeneralName name)
        throws CertPathValidatorException
    {
        switch(name.getTagNo())
        {
        case 1:
            checkPermittedEmail(permittedSubtreesEmail, extractNameAsString(name));
            break;
        case 2:
            checkPermittedDNS(permittedSubtreesDNS, DERIA5String.getInstance(name.getName()).getString());
            break;
        case 4:
            checkPermittedDN(ASN1Sequence.getInstance(name.getName().getDERObject()));
            break;
        case 6:
            checkPermittedURI(permittedSubtreesURI, DERIA5String.getInstance(name.getName()).getString());
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
            checkExcludedEmail(excludedSubtreesEmail, extractNameAsString(name));
            break;
        case 2:
            checkExcludedDNS(excludedSubtreesDNS, DERIA5String.getInstance(name.getName()).getString());
            break;
        case 4:
            checkExcludedDN(ASN1Sequence.getInstance(name.getName().getDERObject()));
            break;
        case 6:
            checkExcludedURI(excludedSubtreesURI, DERIA5String.getInstance(name.getName()).getString());
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
            permittedSubtreesEmail = intersectEmail(permittedSubtreesEmail, extractNameAsString(name));
            break;
        case 2:
            permittedSubtreesDNS = intersectDNS(permittedSubtreesDNS, DERIA5String.getInstance(name.getName()).getString());
            break;
        case 4:
            permittedSubtreesDN = intersectDN(permittedSubtreesDN, ASN1Sequence.getInstance(name.getName().getDERObject()));
            break;
        case 6:
            permittedSubtreesURI = intersectURI(permittedSubtreesURI, DERIA5String.getInstance(name.getName()).getString());
            break;
        case 7:
            byte[] ip = ASN1OctetString.getInstance(name.getName()).getOctets();

            permittedSubtreesIP = intersectIP(permittedSubtreesIP, ip);
        }
    }

    private String extractNameAsString(GeneralName name)
    {
        String email = DERIA5String.getInstance(name.getName()).getString();
        return email;
    }

    public void addExcludedSubtree(GeneralSubtree subtree)
    {
        GeneralName     base = subtree.getBase();

        switch(base.getTagNo())
        {
        case 1:
            excludedSubtreesEmail = unionEmail(excludedSubtreesEmail, DERIA5String.getInstance(base.getName()).getString());
            break;
        case 2:
            excludedSubtreesDNS = unionDNS(excludedSubtreesDNS, DERIA5String.getInstance(base.getName()).getString());
            break;
        case 4:
            excludedSubtreesDN = unionDN(excludedSubtreesDN, (ASN1Sequence)base.getName().getDERObject());
            break;
        case 6:
            excludedSubtreesURI = unionURI(excludedSubtreesURI, DERIA5String.getInstance(base.getName()).getString());
            break;
        case 7:
            excludedSubtreesIP = unionIP(excludedSubtreesIP, ASN1OctetString.getInstance(base.getName()).getOctets());
            break;
        }
    }

    private static byte[] max(byte[] ip1, byte[] ip2)
    {
        for (int i = 0; i < ip1.length; i++)
        {
            if ((ip1[i] & 0xFFFF) > (ip2[i] & 0xFFFF))
            {
                return ip1;
            }
        }
        return ip2;
    }

    private static byte[] min(byte[] ip1, byte[] ip2)
    {
        for (int i = 0; i < ip1.length; i++)
        {
            if ((ip1[i] & 0xFFFF) < (ip2[i] & 0xFFFF))
            {
                return ip1;
            }
        }
        return ip2;
    }

    private static int compareTo(byte[] ip1, byte[] ip2)
    {
        if (Arrays.areEqual(ip1, ip2))
        {
            return 0;
        }
        if (Arrays.areEqual(max(ip1, ip2), ip1))
        {
            return 1;
        }
        return -1;
    }

    private static byte[] or(byte[] ip1, byte[] ip2)
    {
        byte[] temp = new byte[ip1.length];
        for (int i = 0; i < ip1.length; i++)
        {
            temp[i] = (byte)(ip1[i] | ip2[i]);
        }
        return temp;
    }
}
