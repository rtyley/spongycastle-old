package org.bouncycastle.ocsp;

import java.io.ByteArrayOutputStream;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Extension;

public class SingleResp
    implements java.security.cert.X509Extension
{
    SingleResponse  resp;

    public SingleResp(
        SingleResponse  resp)
    {
        this.resp = resp;
    }

    public CertificateID getCertID()
    {
        return new CertificateID(resp.getCertID());
    }

    /**
     * Return the status object for the response - null indicates good.
     * 
     * @return the status object for the response, null if it is good.
     */
    public Object getCertStatus()
    {
        CertStatus  s = resp.getCertStatus();

        if (s.getTagNo() == 0)
        {
            return null;            // good
        }
        else if (s.getTagNo() == 1)
        {
            return new RevokedStatus(RevokedInfo.getInstance(s.getStatus()));
        }

        return new UnknownStatus();
    }

    public Date getThisUpdate()
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");

        return dateF.parse(resp.getThisUpdate().getTime(), new ParsePosition(0));
    }

    /**
     * return the NextUpdate value - note: this is an optional field so may
     * be returned as null.
     */
    public Date getNextUpdate()
    {
        if (resp.getNextUpdate() == null)
        {
            return null;
        }

        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");

        return dateF.parse(resp.getNextUpdate().getTime(), new ParsePosition(0));
    }

    public X509Extensions getSingleExtensions()
    {
        return resp.getSingleExtensions();
    }
    
    /**
     * RFC 2650 doesn't specify any critical extensions so we return true
     * if any are encountered.
     * 
     * @return true if any critical extensions are present.
     */
    public boolean hasUnsupportedCriticalExtension()
    {
        Set extns = getCriticalExtensionOIDs();
        if (extns != null && !extns.isEmpty())
        {
            return true;
        }

        return false;
    }

    private Set getExtensionOIDs(boolean critical)
    {
        Set             set = new HashSet();
        X509Extensions  extensions = this.getSingleExtensions();
        
        if (extensions != null)
        {
            Enumeration     e = extensions.oids();
    
            while (e.hasMoreElements())
            {
                DERObjectIdentifier oid = (DERObjectIdentifier)e.nextElement();
                X509Extension       ext = extensions.getExtension(oid);
    
                if (critical == ext.isCritical())
                {
                    set.add(oid.getId());
                }
            }
        }

        return set;
    }

    public Set getCriticalExtensionOIDs()
    {
        return getExtensionOIDs(true);
    }

    public Set getNonCriticalExtensionOIDs()
    {
        return getExtensionOIDs(false);
    }

    public byte[] getExtensionValue(String oid)
    {
        X509Extensions exts = this.getSingleExtensions();

        if (exts != null)
        {
            X509Extension   ext = exts.getExtension(new DERObjectIdentifier(oid));

            if (ext != null)
            {
                ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
                DEROutputStream dOut = new DEROutputStream(bOut);

                try
                {
                    dOut.writeObject(ext.getValue());

                    return bOut.toByteArray();
                }
                catch (Exception e)
                {
                    throw new RuntimeException("error encoding " + e.toString());
                }
            }
        }

        return null;
    }
}
