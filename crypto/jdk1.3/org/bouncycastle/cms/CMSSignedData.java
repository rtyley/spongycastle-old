package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import org.bouncycastle.jce.cert.CertStore;

import org.bouncycastle.jce.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cms.CMSException;

/**
 * general class for handling a pkcs7-signature message.
 *
 * A simple example of usage - note, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs 
 * matches the given signer...
 *
 * <pre>
 *  CertStore               certs = s.getCertificatesAndCRLs("Collection", "BC");
 *  SignerInformationStore  signers = s.getSignerInfos();
 *  Collection              c = signers.getSigners();
 *  Iterator                it = c.iterator();
 *  
 *  while (it.hasNext())
 *  {
 *      SignerInformation   signer = (SignerInformation)it.next();
 *      Collection          certCollection = certs.getCertificates(signer.getSID());
 *  
 *      Iterator        certIt = certCollection.iterator();
 *      X509Certificate cert = (X509Certificate)certIt.next();
 *  
 *      if (signer.verify(cert.getPublicKey()))
 *      {
 *          verified++;
 *      }   
 *  }
 * </pre>
 */
public class CMSSignedData
{
    SignedData              signedData;
    ContentInfo             contentInfo;
    CMSProcessable          signedContent;
    CertStore               certStore;
    SignerInformationStore  signerInfoStore;

    private static ContentInfo readContentInfo(
        InputStream envelopedData)
        throws CMSException
    {
        try
        {
            ASN1InputStream in = new ASN1InputStream(envelopedData);

            return ContentInfo.getInstance(in.readObject());
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading content.", e);
        }
    }
    
    private CMSSignedData(
        CMSSignedData   c)
    {
        this.signedData = c.signedData;
        this.contentInfo = c.contentInfo;
        this.signedContent = c.signedContent;
        this.certStore = c.certStore;
        this.signerInfoStore = c.signerInfoStore;
    }

    public CMSSignedData(
        byte[]      sigBlock)
        throws CMSException
    {
        this(readContentInfo(new ByteArrayInputStream(sigBlock)));
    }

    public CMSSignedData(
        CMSProcessable  signedContent,
        byte[]          sigBlock)
        throws CMSException
    {
        this(signedContent, readContentInfo(new ByteArrayInputStream(sigBlock)));
    }

    /**
     * base constructor
     *
     * @param signedContent the content that was signed.
     * @param sigData the signature object.
     */
    public CMSSignedData(
        CMSProcessable  signedContent,
        InputStream     sigData)
        throws CMSException
    {
        this(signedContent, readContentInfo(sigData));
    }

    /**
     * base constructor - with encapsulated content
     */
    public CMSSignedData(
        InputStream sigData)
        throws CMSException
    {
        this(readContentInfo(sigData));
    }

    public CMSSignedData(
        CMSProcessable  signedContent,
        ContentInfo     sigData)
    {
        this.signedContent = signedContent;
        this.contentInfo = sigData;
        this.signedData = SignedData.getInstance(contentInfo.getContent());
    }

    public CMSSignedData(
        ContentInfo sigData)
    {
        this.contentInfo = sigData;
        this.signedData = SignedData.getInstance(contentInfo.getContent());

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

    /**
     * return the collection of signers that are associated with the
     * signatures for the message.
     */
    public SignerInformationStore getSignerInfos()
    {
        if (signerInfoStore == null)
        {
            ASN1Set         s = signedData.getSignerInfos();
            ArrayList       signerInfos = new ArrayList();

            for (int i = 0; i != s.size(); i++)
            {
                signerInfos.add(new SignerInformation(SignerInfo.getInstance(s.getObjectAt(i)), signedData.getEncapContentInfo().getContentType(), signedContent));
            }

            signerInfoStore = new SignerInformationStore(signerInfos);
        }

        return signerInfoStore;
    }

    /**
     * return a CertStore containing the certificates and CRLs associated with
     * this message.
     *
     * @exception NoProviderException if the provider requested isn't available.
     * @exception NoSuchAlgorithmException if the cert store isn't available.
     */
    public CertStore getCertificatesAndCRLs(
        String  type,
        String  provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        if (certStore == null)
        {
            ArrayList               certsAndcrls = new ArrayList();
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
            CertificateFactory      cf;

            try
            {
                cf = CertificateFactory.getInstance("X.509", provider);
            }
            catch (CertificateException ex)
            {
                throw new CMSException("can't get certificate factory.", ex);
            }

            //
            // load the certificates and revocation lists if we have any
            //
            ASN1Set s = signedData.getCertificates();

            if (s != null)
            {
                Enumeration e = s.getObjects();

                while (e.hasMoreElements())
                {
                    try
                    {
                        aOut.writeObject(e.nextElement());

                        certsAndcrls.add(cf.generateCertificate(
                            new ByteArrayInputStream(bOut.toByteArray())));
                    }
                    catch (IOException ex)
                    {
                        throw new CMSException(
                                "can't re-encode certificate!", ex);
                    }
                    catch (CertificateException ex)
                    {
                        throw new CMSException(
                                "can't re-encode certificate!", ex);
                    }

                    bOut.reset();
                }
            }

            s = signedData.getCRLs();

            if (s != null)
            {
                Enumeration e = s.getObjects();

                while (e.hasMoreElements())
                {
                    try
                    {
                        aOut.writeObject(e.nextElement());

                        certsAndcrls.add(cf.generateCRL(
                            new ByteArrayInputStream(bOut.toByteArray())));
                    }
                    catch (IOException ex)
                    {
                        throw new CMSException("can't re-encode CRL!", ex);
                    }
                    catch (CRLException ex)
                    {
                        throw new CMSException("can't re-encode CRL!", ex);
                    }

                    bOut.reset();
                }
            }

            try
            {
                certStore = CertStore.getInstance(type, 
                    new CollectionCertStoreParameters(certsAndcrls), provider);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new CMSException("can't setup the CertStore", e);
            }
        }

        return certStore;
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
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(contentInfo);

        return bOut.toByteArray();
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
        ASN1EncodableVector vec = new ASN1EncodableVector();
        
        Iterator    it = signerInformationStore.getSigners().iterator();
        while (it.hasNext())
        {
            vec.add(((SignerInformation)it.next()).toSignerInfo());
        }

        ASN1Set             signers = new DERSet(vec);
        ASN1Sequence        sD = (ASN1Sequence)signedData.signedData.getDERObject();

        vec = new ASN1EncodableVector();
        
        //
        // signers are the last item in the sequence.
        //
        for (int i = 0; i != sD.size() - 1; i++)
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
    
    private static DERObject makeObj(
        byte[]  encoding)
        throws IOException
    {
        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream         aIn = new ASN1InputStream(bIn);

        return aIn.readObject();
    }
    
    /**
     * Replace the certificate and CRL information associated with this
     * CMSSignedData object with the new one passed in.
     * 
     * @param signedData the signed data object to be used as a base.
     * @param certsAndCrls the new certificates and CRLs to be used.
     * @return a new signed data object.
     * @exception CMSException if there is an error processing the CertStore
     */
    public static CMSSignedData replaceCertificatesAndCRLs(
        CMSSignedData   signedData,
        CertStore       certsAndCrls)
        throws CMSException
    {
        //
        // copy
        //
        CMSSignedData   cms = new CMSSignedData(signedData);
        
        //
        // replace the store
        //
        cms.certStore = certsAndCrls;
        
        //
        // replace the certs and crls in the SignedData object
        //
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        try
        {
            Iterator  it = certsAndCrls.getCertificates(null).iterator();

            while (it.hasNext())
            {
                X509Certificate         c = (X509Certificate)it.next();

                v.add(new X509CertificateStructure(
                                        (ASN1Sequence)makeObj(c.getEncoded())));
            }
        }
        catch (CertStoreException e)
        {
            throw new CMSException("error getting certs from certStore", e);
        }
        catch (IOException e)
        {
            throw new CMSException("error processing certs", e);
        }
        catch (CertificateEncodingException e)
        {
            throw new CMSException("error encoding certs", e);
        }

        ASN1Set             certs = null;
        
        if (v.size() > 0)
        {
            certs = new DERSet(v);
        }
        
        v = new ASN1EncodableVector();
        
        try
        {
            Iterator    it = certsAndCrls.getCRLs(null).iterator();

            while (it.hasNext())
            {
                X509CRL                 c = (X509CRL)it.next();

                v.add(new CertificateList(
                                        (ASN1Sequence)makeObj(c.getEncoded())));
            }
        }
        catch (CertStoreException e)
        {
            throw new CMSException("error getting crls from certStore", e);
        }
        catch (IOException e)
        {
            throw new CMSException("error processing crls", e);
        }
        catch (CRLException e)
        {
            throw new CMSException("error encoding crls", e);
        }

        ASN1Set             crls = null;
        
        if (v.size() > 0)
        {
            crls = new DERSet(v);
        }
        
        //
        // replace the CMS structure.
        //
        cms.signedData = new SignedData(signedData.signedData.getDigestAlgorithms(), 
                                   signedData.signedData.getEncapContentInfo(),
                                   certs,
                                   crls,
                                   signedData.signedData.getSignerInfos());
        
        //
        // replace the contentInfo with the new one
        //
        cms.contentInfo = new ContentInfo(cms.contentInfo.getContentType(), cms.signedData);
        
        return cms;
    }
}
