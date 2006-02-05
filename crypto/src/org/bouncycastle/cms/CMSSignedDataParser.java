package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.sasn1.Asn1Object;
import org.bouncycastle.sasn1.Asn1OctetString;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.Asn1Set;
import org.bouncycastle.sasn1.BerTag;
import org.bouncycastle.sasn1.DerSequence;
import org.bouncycastle.sasn1.cms.ContentInfoParser;
import org.bouncycastle.sasn1.cms.SignedDataParser;

/**
 * Parsing class for an CMS Signed Data object from an input stream.
 * <p>
 * Note: that because we are in a streaming mode only one signer can be tried and it is important 
 * that the methods on the parser are called in the appropriate order.
 * </p>
 * <p>
 * A simple example of usage for an encapsulated signature.
 * </p>
 * <p>
 * Two notes: first, in the example below the validity of
 * the certificate isn't verified, just the fact that one of the certs 
 * matches the given signer, and, second, because we are in a streaming
 * mode the order of the operations is important.
 * </p>
 * <pre>
 *      CMSSignedDataParser     sp = new CMSSignedDataParser(encapSigData);
 *
 *      sp.getSignedContent().drain();
 *
 *      CertStore               certs = sp.getCertificatesAndCRLs("Collection", "BC");
 *      SignerInformationStore  signers = sp.getSignerInfos();
 *      
 *      Collection              c = signers.getSigners();
 *      Iterator                it = c.iterator();
 *
 *      while (it.hasNext())
 *      {
 *          SignerInformation   signer = (SignerInformation)it.next();
 *          Collection          certCollection = certs.getCertificates(signer.getSID());
 *
 *          Iterator        certIt = certCollection.iterator();
 *          X509Certificate cert = (X509Certificate)certIt.next();
 *
 *          System.out.println("verify returns: " + signer.verify(cert, "BC"));
 *      }
 * </pre>
 *  Note also: this class does not introduce buffering - if you are processing large files you should create
 *  the parser with:
 *  <pre>
 *          CMSSignedDataParser     ep = new CMSSignedDataParser(new BufferedInputStream(encapSigData, bufSize));
 *  </pre>
 *  where bufSize is a suitably large buffer size.
 */
public class CMSSignedDataParser
    extends CMSContentInfoParser
{
    private SignedDataParser        _signedData;
    private CMSTypedStream          _signedContent;
    private Map                     _digests;
    
    private CertStore               _certStore;
    private SignerInformationStore  _signerInfoStore;

    public CMSSignedDataParser(
        byte[]      sigBlock)
        throws CMSException
    {
        this(readContentInfo(new ByteArrayInputStream(sigBlock)));
    }

    public CMSSignedDataParser(
        CMSTypedStream  signedContent,
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
    public CMSSignedDataParser(
        CMSTypedStream  signedContent,
        InputStream     sigData)
        throws CMSException
    {
        this(signedContent, readContentInfo(sigData));
    }

    /**
     * base constructor - with encapsulated content
     */
    public CMSSignedDataParser(
        InputStream sigData)
        throws CMSException
    {
        this(readContentInfo(sigData));
    }

    CMSSignedDataParser(
        CMSTypedStream  signedContent,
        ContentInfoParser     sigData) 
        throws CMSException
    {
        super(sigData);
        
        try
        {
            this._signedContent = signedContent;
            this._signedData = new SignedDataParser((Asn1Sequence)_contentInfo.getContent(BerTag.SEQUENCE));
            this._digests = new HashMap();
            
            Asn1Set    digAlgs = _signedData.getDigestAlgorithms();
            Asn1Object o;
            
            while ((o = digAlgs.readObject()) != null)
            {
                AlgorithmIdentifier id = AlgorithmIdentifier.getInstance(new ASN1InputStream(((DerSequence)o).getEncoded()).readObject());
                try
                {
                    String        digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(id.getObjectId().toString());
                    MessageDigest dig = MessageDigest.getInstance(digestName);

                    this._digests.put(digestName, dig);
                }
                catch (NoSuchAlgorithmException e)
                {
                     //  ignore
                }
            }
            
            if (_signedContent == null)
            {
                //
                // If the message is simply a certificate chain message getContent() may return null.
                //
                Asn1OctetString octs = (Asn1OctetString)_signedData.getEncapContentInfo().getContent(BerTag.OCTET_STRING);
                
                if (octs != null)
                {
                    this._signedContent = new CMSTypedStream(octs.getOctetStream());
                }
            }
            else
            {
                //
                // content passed in, need to read past empty encapsulated content info object if present
                //
                Asn1OctetString octs = (Asn1OctetString)_signedData.getEncapContentInfo().getContent(BerTag.OCTET_STRING);
                
                if (octs != null)
                {
                    InputStream     in = octs.getOctetStream();
                    
                    while (in.read() >= 0)
                    {
                        // ignore
                    }
                }
            }
        }
        catch (IOException e)
        {
            throw new CMSException("io exception: " + e.getMessage(), e);
        }
        
        if (_digests.isEmpty())
        {
            throw new CMSException("no digests could be created for message.");
        }
    }

    public CMSSignedDataParser(
        ContentInfoParser sigData) 
        throws CMSException
    {
        this(null, sigData);
    }

    /**
     * return the collection of signers that are associated with the
     * signatures for the message.
     * @throws CmsException 
     */
    public SignerInformationStore getSignerInfos() 
        throws CMSException
    {
        if (_signerInfoStore == null)
        {
            List      signerInfos = new ArrayList();
            Map       hashes = new HashMap();
            
            Iterator  it = _digests.keySet().iterator();
            while (it.hasNext())
            {
                Object digestKey = it.next();
                
                hashes.put(digestKey, ((MessageDigest)_digests.get(digestKey)).digest());
            }
            
            try
            {
                Asn1Set         s = _signedData.getSignerInfos();
                Asn1Object      o = null;
                
                while ((o = s.readObject()) != null)
                {
                    DerSequence seq = (DerSequence)o;
                    SignerInfo  info = SignerInfo.getInstance(new ASN1InputStream(seq.getEncoded()).readObject());
                    String      digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(info.getDigestAlgorithm().getObjectId().getId());
                    
                    byte[] hash = (byte[])hashes.get(digestName);
                    
                    signerInfos.add(new SignerInformation(info, new DERObjectIdentifier(_signedContent.getContentType()), null, hash));
                }
            }
            catch (IOException e)
            {
                throw new CMSException("io exception: " + e.getMessage(), e);
            }

            _signerInfoStore = new SignerInformationStore(signerInfos);
        }

        return _signerInfoStore;
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
        if (_certStore == null)
        {
            List                    certsAndcrls = new ArrayList();
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
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
            try
            {
                Asn1Set s = _signedData.getCertificates();
    
                if (s != null)
                {
                    DerSequence seq;
    
                    while ((seq = (DerSequence)s.readObject()) != null)
                    {
                        try
                        {
                            certsAndcrls.add(cf.generateCertificate(
                                new ByteArrayInputStream(seq.getEncoded())));
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
    
                s = _signedData.getCrls();
    
                if (s != null)
                {
                    DerSequence seq;
    
                    while ((seq = (DerSequence)s.readObject()) != null)
                    {
                        try
                        {
                            certsAndcrls.add(cf.generateCRL(
                                new ByteArrayInputStream(seq.getEncoded())));
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
            }
            catch (IOException e)
            {
                throw new CMSException("io exception: " + e.getMessage(), e);
            }

            try
            {
                _certStore = CertStore.getInstance(type, 
                    new CollectionCertStoreParameters(certsAndcrls), provider);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new CMSException("can't setup the CertStore", e);
            }
        }

        return _certStore;
    }
    
    public CMSTypedStream getSignedContent()
    {
        if (_signedContent != null)
        {
            InputStream digStream = _signedContent.getContentStream();
            
            Iterator it = _digests.values().iterator();
            
            while (it.hasNext())
            {
                digStream = new DigestInputStream(digStream, (MessageDigest)it.next());
            }
            
            return new CMSTypedStream(_signedContent.getContentType(), digStream);
        }
        else
        {
            return null;
        }
    }
}
