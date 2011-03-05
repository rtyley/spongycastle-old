package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import org.bouncycastle.jce.X509Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * The following extensions are listed in RFC 2459 as relevant to CRLs
 *
 * Authority Key Identifier
 * Issuer Alternative Name
 * CRL Number
 * Delta CRL Indicator (critical)
 * Issuing Distribution Point (critical)
 */
public class X509CRLObject
    extends X509CRL
{
    private CertificateList c;
    private String sigAlgName;
    private byte[] sigAlgParams;
    private boolean isIndirect;

    public X509CRLObject(
        CertificateList c)
        throws CRLException
    {
        this.c = c;
        
        try
        {
            this.sigAlgName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
            
            if (c.getSignatureAlgorithm().getParameters() != null)
            {
                this.sigAlgParams = ((ASN1Encodable)c.getSignatureAlgorithm().getParameters()).getDEREncoded();
            }
            else
            {
                this.sigAlgParams = null;
            }

            this.isIndirect = isIndirectCRL();
        }
        catch (Exception e)
        {
            throw new CRLException("CRL contents invalid: " + e);
        }
    }

    /**
     * Will return true if any extensions are present and marked
     * as critical as we currently dont handle any extensions!
     */
    public boolean hasUnsupportedCriticalExtension()
    {
        Set extns = getCriticalExtensionOIDs();
        return extns != null && !extns.isEmpty();
    }

    private Set getExtensionOIDs(boolean critical)
    {
        if (this.getVersion() == 2)
        {
            Set             set = new HashSet();
            X509Extensions  extensions = c.getTBSCertList().getExtensions();
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

            return set;
        }

        return null;
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
        X509Extensions exts = c.getTBSCertList().getExtensions();

        if (exts != null)
        {
            X509Extension   ext = exts.getExtension(new DERObjectIdentifier(oid));

            if (ext != null)
            {
                try
                {
                    return ext.getValue().getEncoded();
                }
                catch (Exception e)
                {
                    throw new IllegalStateException("error parsing " + e.toString());
                }
            }
        }

        return null;
    }

    public byte[] getEncoded()
        throws CRLException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        DEROutputStream            dOut = new DEROutputStream(bOut);

        try
        {
            dOut.writeObject(c);

            return bOut.toByteArray();
        }
        catch (IOException e)
        {
            throw new CRLException(e.toString());
        }
    }

    public void verify(PublicKey key)
        throws CRLException,  NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException
    {
        verify(key, BouncyCastleProvider.PROVIDER_NAME);
    }

    public void verify(PublicKey key, String sigProvider)
        throws CRLException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException
    {
        if (!c.getSignatureAlgorithm().equals(c.getTBSCertList().getSignature()))
        {
            throw new CRLException("Signature algorithm on CertificateList does not match TBSCertList.");
        }

        Signature sig = Signature.getInstance(getSigAlgName(), sigProvider);

        sig.initVerify(key);
        sig.update(this.getTBSCertList());
        if (!sig.verify(this.getSignature()))
        {
            throw new SignatureException("CRL does not verify with supplied public key.");
        }
    }

    public int getVersion()
    {
        return c.getVersion();
    }

    public Principal getIssuerDN()
    {
        return new X509Principal(c.getIssuer());
    }

    public Date getThisUpdate()
    {
        return c.getThisUpdate().getDate();
    }

    public Date getNextUpdate()
    {
        if (c.getNextUpdate() != null)
        {
            return c.getNextUpdate().getDate();
        }

        return null;
    }

    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber)
    {
        TBSCertList.CRLEntry[] certs = c.getRevokedCertificates();

        if (certs != null)
        {
            X509Principal previousCertificateIssuer = (X509Principal)getIssuerDN();
            for (int i = 0; i < certs.length; i++)
            {
                X509CRLEntryObject crlentry = new X509CRLEntryObject(certs[i],
                        isIndirect, previousCertificateIssuer);
                previousCertificateIssuer = crlentry.getCertificateIssuer();
                if (crlentry.getSerialNumber().equals(serialNumber))
                {
                    return crlentry;
                }
            }
        }

        return null;
    }

    public Set getRevokedCertificates()
    {
        TBSCertList.CRLEntry[] certs = c.getRevokedCertificates();

        if (certs != null)
        {
            Set set = new HashSet();
            X509Principal previousCertificateIssuer = (X509Principal)getIssuerDN();
            for (int i = 0; i < certs.length; i++)
            {
                X509CRLEntryObject crlentry = new X509CRLEntryObject(certs[i],
                        isIndirect, previousCertificateIssuer);
                set.add(crlentry);
                previousCertificateIssuer = crlentry.getCertificateIssuer();
            }

            return set;
        }

        return null;
    }
  
    public byte[] getTBSCertList()
        throws CRLException
    {
        try
        {
            return c.getTBSCertList().getEncoded("DER");
        }
        catch (IOException e)
        {
            throw new CRLException(e.toString());
        }
    }

    public byte[] getSignature()
    {
        return c.getSignature().getBytes();
    }

    public String getSigAlgName()
    {
        return sigAlgName;
    }

    public String getSigAlgOID()
    {
        return c.getSignatureAlgorithm().getObjectId().getId();
    }

    public byte[] getSigAlgParams()
    {
        if (sigAlgParams != null)
        {
            byte[] tmp = new byte[sigAlgParams.length];
            
            System.arraycopy(sigAlgParams, 0, tmp, 0, tmp.length);
            
            return tmp;
        }
        
        return null;
    }

    /**
     * Returns a string representation of this CRL.
     *
     * @return a string representation of this CRL.
     */
    public String toString()
    {
        return "X.509 CRL";
    }

    /**
     * Checks whether the given certificate is on this CRL.
     *
     * @param cert the certificate to check for.
     * @return true if the given certificate is on this CRL,
     * false otherwise.
     */
    public boolean isRevoked(Certificate cert)
    {
        if (!cert.getType().equals("X.509"))
        {
            throw new RuntimeException("X.509 CRL used with non X.509 Cert");
        }

        TBSCertList.CRLEntry[] certs = c.getRevokedCertificates();

        if (certs != null)
        {
            BigInteger serial = ((X509Certificate)cert).getSerialNumber();

            for (int i = 0; i < certs.length; i++)
            {
                if (certs[i].getUserCertificate().getValue().equals(serial))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isIndirectCRL()
        throws CRLException
    {
        byte[] idp = getExtensionValue(X509Extensions.IssuingDistributionPoint.getId());
        boolean isIndirect = false;
        try
        {
            if (idp != null)
            {
                isIndirect = IssuingDistributionPoint.getInstance(
                        X509ExtensionUtil.fromExtensionValue(idp))
                        .isIndirectCRL();
            }
        }
        catch (IOException e)
        {
            throw new CRLException(
                    "Exception reading IssuingDistributionPoint" + e);
        }

        return isIndirect;
    }
}

