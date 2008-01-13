package org.bouncycastle.tsp;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Collection;
import java.util.Date;
import org.bouncycastle.jce.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

public class TimeStampToken
{
    CMSSignedData tsToken;

    SignerInformation tsaSignerInfo;

    Date genTime;

    TimeStampTokenInfo tstInfo;
    
    CertID   certID;

    public TimeStampToken(ContentInfo contentInfo)
        throws TSPException, IOException
    {
        this(new CMSSignedData(contentInfo));
    }   
    
    public TimeStampToken(CMSSignedData signedData)
        throws TSPException, IOException
    {
        this.tsToken = signedData;

        if (!this.tsToken.getSignedContentTypeOID().equals(PKCSObjectIdentifiers.id_ct_TSTInfo.getId()))
        {
            throw new TSPValidationException("ContentInfo object not for a time stamp.");
        }
        
        Collection signers = tsToken.getSignerInfos().getSigners();

        if (signers.size() != 1)
        {
            throw new IllegalArgumentException("Time-stamp token signed by "
                    + signers.size()
                    + " signers, but it must contain just the TSA signature.");
        }

        tsaSignerInfo = (SignerInformation)signers.iterator().next();

        try
        {
            CMSProcessable content = tsToken.getSignedContent();
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            content.write(bOut);

            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bOut.toByteArray()));

            this.tstInfo = new TimeStampTokenInfo(TSTInfo.getInstance(aIn.readObject()));
            
            Attribute   attr = tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificate);

            if (attr != null)
            {
                SigningCertificate    signCert = SigningCertificate.getInstance(attr.getAttrValues().getObjectAt(0));

                this.certID = new CertID(ESSCertID.getInstance(signCert.getCerts()[0]));
            }
            else
            {
                attr = tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);

                if (attr == null)
                {
                    throw new TSPValidationException("no signing certificate attribute found, time stamp invalid.");
                }

                SigningCertificateV2 signCertV2 = SigningCertificateV2.getInstance(attr.getAttrValues().getObjectAt(0));

                this.certID = new CertID(ESSCertIDv2.getInstance(signCertV2.getCerts()[0]));
            }
            

        }
        catch (CMSException e)
        {
            throw new TSPException(e.getMessage(), e.getUnderlyingException());
        }
    }

    public TimeStampTokenInfo getTimeStampInfo()
    {
        return tstInfo;
    }

    public SignerId getSID()
    {
        return tsaSignerInfo.getSID();
    }
    
    public AttributeTable getSignedAttributes()
    {
        return tsaSignerInfo.getSignedAttributes();
    }

    public AttributeTable getUnsignedAttributes()
    {
        return tsaSignerInfo.getUnsignedAttributes();
    }

    public CertStore getCertificatesAndCRLs(
        String type,
        String provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return tsToken.getCertificatesAndCRLs(type, provider);
    }

    /**
     * Validate the time stamp token.
     * <p>
     * To be valid the token must be signed by the passed in certificate and
     * the certificate must be the one referred to by the SigningCertificate 
     * attribute included in the hashed attributes of the token. The
     * certificate must also have the ExtendedKeyUsageExtension with only
     * KeyPurposeId.id_kp_timeStamping and have been valid at the time the
     * timestamp was created.
     * </p>
     * <p>
     * A successful call to validate means all the above are true.
     * </p>
     */
    public void validate(
        X509Certificate cert,
        String provider)
        throws TSPException, TSPValidationException,
        CertificateExpiredException, CertificateNotYetValidException, NoSuchProviderException
    {
        try
        {
            if (!MessageDigest.isEqual(certID.getCertHash(), MessageDigest.getInstance(certID.getHashAlgorithm()).digest(cert.getEncoded())))
            {
                throw new TSPValidationException("certificate hash does not match certID hash.");
            }
            
            if (certID.getIssuerSerial() != null)
            {
                if (!certID.getIssuerSerial().getSerial().getValue().equals(cert.getSerialNumber()))
                {
                    throw new TSPValidationException("certificate serial number does not match certID for signature.");
                }
                
                GeneralName[]   names = certID.getIssuerSerial().getIssuer().getNames();
                X509Principal   principal = PrincipalUtil.getIssuerX509Principal(cert);
                boolean         found = false;
                
                for (int i = 0; i != names.length; i++)
                {
                    if (names[i].getTagNo() == 4 && new X509Principal(X509Name.getInstance(names[i].getName())).equals(principal))
                    {
                        found = true;
                        break;
                    }
                }
                
                if (!found)
                {
                    throw new TSPValidationException("certificate name does not match certID for signature. ");
                }
            }
            
            TSPUtil.validateCertificate(cert);
            
            cert.checkValidity(tstInfo.getGenTime());

            if (!tsaSignerInfo.verify(cert, provider))
            {
                throw new TSPValidationException("signature not created by certificate.");
            }
        }
        catch (CMSException e)
        {
            if (e.getUnderlyingException() != null)
            {
                throw new TSPException(e.getMessage(), e.getUnderlyingException());
            }
            else
            {
                throw new TSPException("CMS exception: " + e, e);
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new TSPException("cannot find algorithm: " + e, e);
        }
        catch (CertificateEncodingException e)
        {
            throw new TSPException("problem processing certificate: " + e, e);
        }
    }

    /**
     * Return the underlying CMSSignedData object.
     * 
     * @return the underlying CMS structure.
     */
    public CMSSignedData toCMSSignedData()
    {
        return tsToken;
    }
    
    /**
     * Return a ASN.1 encoded byte stream representing the encoded object.
     * 
     * @throws IOException if encoding fails.
     */
    public byte[] getEncoded() 
        throws IOException
    {
        return tsToken.getEncoded();
    }

    // perhaps this should be done using an interface on the ASN.1 classes...
    private class CertID
    {
        private ESSCertID certID;
        private ESSCertIDv2 certIDv2;

        CertID(ESSCertID certID)
        {
            this.certID = certID;
            this.certIDv2 = null;
        }

        CertID(ESSCertIDv2 certID)
        {
            this.certIDv2 = certID;
            this.certID = null;
        }

        public String getHashAlgorithm()
        {
            if (certID != null)
            {
                return "SHA-1";
            }
            else
            {
                if (NISTObjectIdentifiers.id_sha256.equals(certIDv2.getHashAlgorithm().getObjectId()))
                {
                    return "SHA-256";
                }
                return certIDv2.getHashAlgorithm().getObjectId().getId();
            }
        }

        public byte[] getCertHash()
        {
            if (certID != null)
            {
                return certID.getCertHash();
            }
            else
            {
                return certIDv2.getCertHash();
            }
        }

        public IssuerSerial getIssuerSerial()
        {
            if (certID != null)
            {
                return certID.getIssuerSerial();
            }
            else
            {
                return certIDv2.getIssuerSerial();
            }
        }
    }
}
