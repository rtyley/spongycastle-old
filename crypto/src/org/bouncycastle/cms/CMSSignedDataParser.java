package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERSetParser;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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
        this(new ByteArrayInputStream(sigBlock));
    }

    public CMSSignedDataParser(
        CMSTypedStream  signedContent,
        byte[]          sigBlock)
        throws CMSException
    {
        this(signedContent, new ByteArrayInputStream(sigBlock));
    }

    /**
     * base constructor - with encapsulated content
     */
    public CMSSignedDataParser(
        InputStream sigData)
        throws CMSException
    {
        this(null, sigData);
    }

    /**
     * base constructor
     *
     * @param signedContent the content that was signed.
     * @param sigData the signature object stream.
     */
    public CMSSignedDataParser(
        CMSTypedStream  signedContent,
        InputStream     sigData) 
        throws CMSException
    {
        super(sigData);
        
        try
        {
            _signedContent = signedContent;
            _signedData = SignedDataParser.getInstance(_contentInfo.getContent(DERTags.SEQUENCE));
            _digests = new HashMap();
            
            ASN1SetParser digAlgs = _signedData.getDigestAlgorithms();
            DEREncodable  o;
            
            while ((o = digAlgs.readObject()) != null)
            {
                AlgorithmIdentifier id = AlgorithmIdentifier.getInstance(o.getDERObject());
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
                ASN1OctetStringParser octs = (ASN1OctetStringParser)_signedData.getEncapContentInfo().getContent(DERTags.OCTET_STRING);
                
                if (octs != null)
                {
                    _signedContent = new CMSTypedStream(octs.getOctetStream());
                }
            }
            else
            {
                //
                // content passed in, need to read past empty encapsulated content info object if present
                //
                ASN1OctetStringParser octs = (ASN1OctetStringParser)_signedData.getEncapContentInfo().getContent(DERTags.OCTET_STRING);
                
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

    /**
     * return the collection of signers that are associated with the
     * signatures for the message.
     * @throws CMSException 
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
                ASN1SetParser     s = _signedData.getSignerInfos();
                DEREncodable      o;
                
                while ((o = s.readObject()) != null)
                {
                    SignerInfo info = SignerInfo.getInstance(o.getDERObject());
                    String     digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(info.getDigestAlgorithm().getObjectId().getId());
                    
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
     * @exception NoSuchProviderException if the provider requested isn't available.
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
                ASN1SetParser s = _signedData.getCertificates();
    
                if (s != null)
                {
                    ASN1Set set = ASN1Set.getInstance(s.getDERObject());

                    for (Enumeration en = set.getObjects(); en.hasMoreElements();)
                    {
                        ASN1Sequence seq = (ASN1Sequence)en.nextElement();

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
                    ASN1Set set = ASN1Set.getInstance(s.getDERObject());

                    for (Enumeration en = set.getObjects(); en.hasMoreElements();)
                    {
                        ASN1Sequence seq = (ASN1Sequence)en.nextElement();
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


    /**
     * Replace the signerinformation store associated with the passed
     * in message contained in the stream original with the new one passed in.
     * You would probably only want to do this if you wanted to change the unsigned
     * attributes associated with a signer, or perhaps delete one.
     * <p>
     * The output stream is returned unclosed.
     * </p>
     * @param original the signed data stream to be used as a base.
     * @param signerInformationStore the new signer information store to use.
     * @param out the stream to write the new signed data object to.
     * @return out.
     */
    public static OutputStream replaceSigners(
        InputStream             original,
        SignerInformationStore  signerInformationStore,
        OutputStream            out)
        throws CMSException, IOException
    {
        ASN1StreamParser in = new ASN1StreamParser(original, CMSUtils.getMaximumMemory());
        ContentInfoParser contentInfo = new ContentInfoParser((ASN1SequenceParser)in.readObject());
        SignedDataParser signedData = SignedDataParser.getInstance(contentInfo.getContent(DERTags.SEQUENCE));

        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.signedData);

        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        // version number
        sigGen.addObject(signedData.getVersion());

        // digests
        signedData.getDigestAlgorithms().getDERObject();  // skip old ones

        ASN1EncodableVector digestAlgs = new ASN1EncodableVector();

        for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext();)
        {
            SignerInformation        signer = (SignerInformation)it.next();
            AlgorithmIdentifier     digAlgId;

            digAlgId = makeAlgId(signer.getDigestAlgOID(), signer.getDigestAlgParams());

            digestAlgs.add(digAlgId);
        }

        sigGen.getRawOutputStream().write(new DERSet(digestAlgs).getEncoded());

        // encap content info
        ContentInfoParser encapContentInfo = signedData.getEncapContentInfo();

        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());

        eiGen.addObject(encapContentInfo.getContentType());

        ASN1OctetStringParser octs = (ASN1OctetStringParser)encapContentInfo.getContent(DERTags.OCTET_STRING);

        if (octs != null)
        {
            BEROctetStringGenerator octGen = new BEROctetStringGenerator(eiGen.getRawOutputStream(), 0, true);
            byte[]                  inBuffer = new byte[4096];
            byte[]                  outBuffer = new byte[4096];
            InputStream             inOctets = octs.getOctetStream();
            OutputStream            outOctets = octGen.getOctetOutputStream(outBuffer);

            int len;
            while ((len = inOctets.read(inBuffer, 0, outBuffer.length)) >= 0)
            {
                outOctets.write(inBuffer, 0, len);
            }

            outOctets.close();
        }

        eiGen.close();

        ASN1SetParser set = signedData.getCertificates();

        if (set instanceof BERSetParser)
        {
            sigGen.getRawOutputStream().write(new BERTaggedObject(false, 0, set.getDERObject()).getEncoded());
        }
        else if (set != null)
        {
            sigGen.getRawOutputStream().write(new DERTaggedObject(false, 0, set.getDERObject()).getEncoded());
        }

        set = signedData.getCrls();

        if (set instanceof BERSetParser)
        {
            sigGen.getRawOutputStream().write(new BERTaggedObject(false, 1, set.getDERObject()).getEncoded());
        }
        else if (set != null)
        {
            sigGen.getRawOutputStream().write(new DERTaggedObject(false, 1, set.getDERObject()).getEncoded());
        }

        ASN1EncodableVector signerInfos = new ASN1EncodableVector();
        for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext();)
        {
            SignerInformation        signer = (SignerInformation)it.next();

            signerInfos.add(signer.toSignerInfo());
        }

        sigGen.getRawOutputStream().write(new DERSet(signerInfos).getEncoded());

        sigGen.close();

        sGen.close();

        return out;
    }

    /**
     * Replace the certificate and CRL information associated with this
     * CMSSignedData object with the new one passed in.
     * <p>
     * The output stream is returned unclosed.
     * </p>
     * @param original the signed data stream to be used as a base.
     * @param certsAndCrls the new certificates and CRLs to be used.
     * @param out the stream to write the new signed data object to.
     * @return out.
     * @exception CMSException if there is an error processing the CertStore
     */
    public static OutputStream replaceCertificatesAndCRLs(
        InputStream   original,
        CertStore     certsAndCrls,
        OutputStream  out)
        throws CMSException, IOException
    {
        ASN1StreamParser in = new ASN1StreamParser(original, CMSUtils.getMaximumMemory());
        ContentInfoParser contentInfo = new ContentInfoParser((ASN1SequenceParser)in.readObject());
        SignedDataParser signedData = SignedDataParser.getInstance(contentInfo.getContent(DERTags.SEQUENCE));

        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.signedData);

        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        // version number
        sigGen.addObject(signedData.getVersion());

        // digests
        sigGen.getRawOutputStream().write(signedData.getDigestAlgorithms().getDERObject().getEncoded());

        // encap content info
        ContentInfoParser encapContentInfo = signedData.getEncapContentInfo();

        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());

        eiGen.addObject(encapContentInfo.getContentType());

        ASN1OctetStringParser octs = (ASN1OctetStringParser)encapContentInfo.getContent(DERTags.OCTET_STRING);

        if (octs != null)
        {
            BEROctetStringGenerator octGen = new BEROctetStringGenerator(eiGen.getRawOutputStream(), 0, true);
            byte[]                  inBuffer = new byte[4096];
            byte[]                  outBuffer = new byte[4096];
            InputStream             inOctets = octs.getOctetStream();
            OutputStream            outOctets = octGen.getOctetOutputStream(outBuffer);

            int len;
            while ((len = inOctets.read(inBuffer, 0, outBuffer.length)) >= 0)
            {
                outOctets.write(inBuffer, 0, len);
            }

            outOctets.close();
        }

        eiGen.close();

        //
        // skip existing certs and CRLs
        //
        ASN1SetParser set = signedData.getCertificates();

        if (set != null)
        {
            set.getDERObject();
        }

        set = signedData.getCrls();

        if (set != null)
        {
            set.getDERObject();
        }

        //
        // replace the certs and crls in the SignedData object
        //
        ASN1EncodableVector v = new ASN1EncodableVector();

        try
        {
            Iterator  it = certsAndCrls.getCertificates(null).iterator();

            while (it.hasNext())
            {
                X509Certificate c = (X509Certificate)it.next();

                v.add(makeObj(c.getEncoded()));
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

        if (v.size() > 0)
        {
            sigGen.getRawOutputStream().write(new DERTaggedObject(false, 0, new DERSet(v)).getEncoded());
        }

        v = new ASN1EncodableVector();

        try
        {
            Iterator    it = certsAndCrls.getCRLs(null).iterator();

            while (it.hasNext())
            {
                X509CRL c = (X509CRL)it.next();

                v.add(makeObj(c.getEncoded()));
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

        if (v.size() > 0)
        {
            sigGen.getRawOutputStream().write(new DERTaggedObject(false, 1, new DERSet(v)).getEncoded());
        }

        sigGen.getRawOutputStream().write(signedData.getSignerInfos().getDERObject().getEncoded());

        sigGen.close();

        sGen.close();

        return out;
    }

    private static DERObject makeObj(
        byte[]  encoding)
        throws IOException
    {
        if (encoding == null)
        {
            return null;
        }

        ASN1InputStream         aIn = new ASN1InputStream(encoding);

        return aIn.readObject();
    }

    private static AlgorithmIdentifier makeAlgId(
        String  oid,
        byte[]  params)
        throws IOException
    {
        if (params != null)
        {
            return new AlgorithmIdentifier(
                            new DERObjectIdentifier(oid), makeObj(params));
        }
        else
        {
            return new AlgorithmIdentifier(
                            new DERObjectIdentifier(oid), new DERNull());
        }
    }
}
