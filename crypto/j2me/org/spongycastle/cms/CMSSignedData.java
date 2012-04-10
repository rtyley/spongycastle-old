package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;


/**
 * general class for handling a pkcs7-signature message.
 *
 * A simple example of usage - note, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs 
 * matches the given signer...
 *
 * <pre>
 *  Store                   certStore = s.getCertificates();
 *  SignerInformationStore  signers = s.getSignerInfos();
 *  Collection              c = signers.getSigners();
 *  Iterator                it = c.iterator();
 *  
 *  while (it.hasNext())
 *  {
 *      SignerInformation   signer = (SignerInformation)it.next();
 *      Collection          certCollection = certStore.getMatches(signer.getSID());
 *
 *      Iterator              certIt = certCollection.iterator();
 *      X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
 *  
 *      if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)))
 *      {
 *          verified++;
 *      }   
 *  }
 * </pre>
 */
public class CMSSignedData
{
    private static final CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;
    
    SignedData              signedData;
    ContentInfo             contentInfo;
    CMSProcessable          signedContent;
    SignerInformationStore  signerInfoStore;

    private Map             hashes;

    private CMSSignedData(
        CMSSignedData   c)
    {
        this.signedData = c.signedData;
        this.contentInfo = c.contentInfo;
        this.signedContent = c.signedContent;
        this.signerInfoStore = c.signerInfoStore;
    }

    public CMSSignedData(
        byte[]      sigBlock)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(sigBlock));
    }

    public CMSSignedData(
        CMSProcessable  signedContent,
        byte[]          sigBlock)
        throws CMSException
    {
        this(signedContent, CMSUtils.readContentInfo(sigBlock));
    }

    /**
     * Content with detached signature, digests precomputed
     *
     * @param hashes a map of precomputed digests for content indexed by name of hash.
     * @param sigBlock the signature object.
     */
    public CMSSignedData(
        Map     hashes,
        byte[]  sigBlock)
        throws CMSException
    {
        this(hashes, CMSUtils.readContentInfo(sigBlock));
    }

    /**
     * base constructor - content with detached signature.
     *
     * @param signedContent the content that was signed.
     * @param sigData the signature object.
     */
    public CMSSignedData(
        CMSProcessable  signedContent,
        InputStream     sigData)
        throws CMSException
    {
        this(signedContent, CMSUtils.readContentInfo(new ASN1InputStream(sigData)));
    }

    /**
     * base constructor - with encapsulated content
     */
    public CMSSignedData(
        InputStream sigData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(sigData));
    }

    public CMSSignedData(
        CMSProcessable  signedContent,
        ContentInfo     sigData)
        throws CMSException
    {
        this.signedContent = signedContent;
        this.contentInfo = sigData;
        this.signedData = getSignedData();
    }

    public CMSSignedData(
        Map             hashes,
        ContentInfo     sigData)
        throws CMSException
    {
        this.hashes = hashes;
        this.contentInfo = sigData;
        this.signedData = getSignedData();
    }

    public CMSSignedData(
        ContentInfo sigData)
        throws CMSException
    {
        this.contentInfo = sigData;
        this.signedData = getSignedData();

        //
        // this can happen if the signed message is sent simply to send a
        // certificate chain.
        //
        if (signedData.getEncapContentInfo().getContent() != null)
        {
            this.signedContent = new CMSProcessableByteArray(
                    ((ASN1OctetString)(signedData.getEncapContentInfo()
                                                .getContent())).getOctets());
        }
        else
        {
            this.signedContent = null;
        }
    }

    private SignedData getSignedData()
        throws CMSException
    {
        try
        {
            return SignedData.getInstance(contentInfo.getContent());
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
        }
    }

    /**
     * Return the version number for this object
     */
    public int getVersion()
    {
        return signedData.getVersion().getValue().intValue();
    }

    /**
     * return the collection of signers that are associated with the
     * signatures for the message.
     */
    public SignerInformationStore getSignerInfos()
    {
        if (signerInfoStore == null)
        {
            ASN1Set         s = signedData.getSignerInfos();
            List            signerInfos = new ArrayList();
            SignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();

            for (int i = 0; i != s.size(); i++)
            {
                SignerInfo info = SignerInfo.getInstance(s.getObjectAt(i));
                ASN1ObjectIdentifier contentType = signedData.getEncapContentInfo().getContentType();

                if (hashes == null)
                {
                    signerInfos.add(new SignerInformation(info, contentType, signedContent, null));
                }
                else
                {
                    Object obj = hashes.keySet().iterator().next();
                    byte[] hash = (obj instanceof String) ? (byte[])hashes.get(info.getDigestAlgorithm().getAlgorithm().getId()) : (byte[])hashes.get(info.getDigestAlgorithm().getAlgorithm());

                    signerInfos.add(new SignerInformation(info, contentType, null, hash));
                }
            }

            signerInfoStore = new SignerInformationStore(signerInfos);
        }

        return signerInfoStore;
    }

    public Store getCertificates()
    {
        ASN1Set certSet = signedData.getCertificates();

        if (certSet != null)
        {
            List    certList = new ArrayList(certSet.size());

            for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1Sequence)
                {
                    certList.add(new X509CertificateHolder(Certificate.getInstance(obj)));
                }
            }

            return new CollectionStore(certList);
        }

        return new CollectionStore(new ArrayList());
    }

    public Store getCRLs()
    {
        ASN1Set crlSet = signedData.getCRLs();

        if (crlSet != null)
        {
            List    crlList = new ArrayList(crlSet.size());

            for (Enumeration en = crlSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1Sequence)
                {
                    crlList.add(new X509CRLHolder(CertificateList.getInstance(obj)));
                }
            }

            return new CollectionStore(crlList);
        }

        return new CollectionStore(new ArrayList());
    }

    public Store getAttributeCertificates()
    {
        ASN1Set certSet = signedData.getCertificates();

        if (certSet != null)
        {
            List    certList = new ArrayList(certSet.size());

            for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1TaggedObject)
                {
                    certList.add(new X509AttributeCertificateHolder(AttributeCertificate.getInstance(((ASN1TaggedObject)obj).getObject())));
                }
            }

            return new CollectionStore(certList);
        }

        return new CollectionStore(new ArrayList());
    }

    /**
     * Return the a string representation of the OID associated with the
     * encapsulated content info structure carried in the signed data.
     * 
     * @return the OID for the content type.
     */
    public String getSignedContentTypeOID()
    {
        return signedData.getEncapContentInfo().getContentType().getId();
    }
    
    public CMSProcessable getSignedContent()
    {
        return signedContent;
    }

    /**
     * return the ContentInfo
     * @deprecated use toASN1Structure()
     */
    public ContentInfo getContentInfo()
    {
        return contentInfo;
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure()
    {
        return contentInfo;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }
    
    /**
     * Replace the signerinformation store associated with this
     * CMSSignedData object with the new one passed in. You would
     * probably only want to do this if you wanted to change the unsigned 
     * attributes associated with a signer, or perhaps delete one.
     * 
     * @param signedData the signed data object to be used as a base.
     * @param signerInformationStore the new signer information store to use.
     * @return a new signed data object.
     */
    public static CMSSignedData replaceSigners(
        CMSSignedData           signedData,
        SignerInformationStore  signerInformationStore)
    {
        //
        // copy
        //
        CMSSignedData   cms = new CMSSignedData(signedData);
        
        //
        // replace the store
        //
        cms.signerInfoStore = signerInformationStore;

        //
        // replace the signers in the SignedData object
        //
        ASN1EncodableVector digestAlgs = new ASN1EncodableVector();
        ASN1EncodableVector vec = new ASN1EncodableVector();
        
        Iterator    it = signerInformationStore.getSigners().iterator();
        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));
            vec.add(signer.toASN1Structure());
        }

        ASN1Set             digests = new DERSet(digestAlgs);
        ASN1Set             signers = new DERSet(vec);
        ASN1Sequence        sD = (ASN1Sequence)signedData.signedData.toASN1Primitive();

        vec = new ASN1EncodableVector();
        
        //
        // signers are the last item in the sequence.
        //
        vec.add(sD.getObjectAt(0)); // version
        vec.add(digests);

        for (int i = 2; i != sD.size() - 1; i++)
        {
            vec.add(sD.getObjectAt(i));
        }
        
        vec.add(signers);
        
        cms.signedData = SignedData.getInstance(new BERSequence(vec));
        
        //
        // replace the contentInfo with the new one
        //
        cms.contentInfo = new ContentInfo(cms.contentInfo.getContentType(), cms.signedData);
        
        return cms;
    }

    /**
     * Replace the certificate and CRL information associated with this
     * CMSSignedData object with the new one passed in.
     *
     * @param signedData the signed data object to be used as a base.
     * @param certificates the new certificates to be used.
     * @param attrCerts the new attribute certificates to be used.
     * @param crls the new CRLs to be used.
     * @return a new signed data object.
     * @exception CMSException if there is an error processing the CertStore
     */
    public static CMSSignedData replaceCertificatesAndCRLs(
        CMSSignedData   signedData,
        Store           certificates,
        Store           attrCerts,
        Store           crls)
        throws CMSException
    {
        //
        // copy
        //
        CMSSignedData   cms = new CMSSignedData(signedData);

        //
        // replace the certs and crls in the SignedData object
        //
        ASN1Set certSet = null;
        ASN1Set crlSet = null;

        if (certificates != null || attrCerts != null)
        {
            List certs = new ArrayList();

            if (certificates != null)
            {
                certs.addAll(CMSUtils.getCertificatesFromStore(certificates));
            }
            if (attrCerts != null)
            {
                certs.addAll(CMSUtils.getAttributeCertificatesFromStore(attrCerts));   
            }

            ASN1Set set = CMSUtils.createBerSetFromList(certs);

            if (set.size() != 0)
            {
                certSet = set;
            }
        }

        if (crls != null)
        {
            ASN1Set set = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(crls));

            if (set.size() != 0)
            {
                crlSet = set;
            }
        }

        //
        // replace the CMS structure.
        //
        cms.signedData = new SignedData(signedData.signedData.getDigestAlgorithms(),
                                   signedData.signedData.getEncapContentInfo(),
                                   certSet,
                                   crlSet,
                                   signedData.signedData.getSignerInfos());

        //
        // replace the contentInfo with the new one
        //
        cms.contentInfo = new ContentInfo(cms.contentInfo.getContentType(), cms.signedData);

        return cms;
    }
}
