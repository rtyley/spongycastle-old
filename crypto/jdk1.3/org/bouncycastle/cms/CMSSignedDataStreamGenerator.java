package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.sasn1.Asn1Integer;
import org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import org.bouncycastle.sasn1.BerOctetStringGenerator;
import org.bouncycastle.sasn1.BerSequenceGenerator;

/**
 * General class for generating a pkcs7-signature message stream.
 * <p>
 * A simple example of usage.
 * </p>
 * <pre>
 *      CertStore                    certs...
 *      CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
 *  
 *      gen.addSigner(privateKey, cert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "BC");
 *  
 *      gen.addCertificatesAndCRLs(certs);
 *  
 *      OutputStream sigOut = gen.open(bOut);
 *  
 *      sigOut.write("Hello World!".getBytes());
 *      
 *      sigOut.close();
 * </pre>
 */
public class CMSSignedDataStreamGenerator
    extends CMSSignedGenerator
{
    private List  _certs = new ArrayList();
    private List  _crls = new ArrayList();
    private List  _signerInfs = new ArrayList();
    private List  _signers = new ArrayList();
    private List  _digests = new ArrayList();
    private int   _bufferSize;
    
    static class DigOutputStream
        extends OutputStream
    {
        MessageDigest   dig;

        public DigOutputStream(
            MessageDigest   dig)
        {
            this.dig = dig;
        }

        public void write(
            byte[]  b,
            int     off,
            int     len)
            throws IOException
        {
            dig.update(b, off, len);
        }

        public void write(
            int b)
            throws IOException
        {
            dig.update((byte)b);
        }
    }

    static class SigOutputStream
        extends OutputStream
    {
        Signature   sig;

        public SigOutputStream(
            Signature   sig)
        {
            this.sig = sig;
        }

        public void write(
            byte[]  b,
            int     off,
            int     len)
            throws IOException
        {
            try
            {
                sig.update(b, off, len);
            }
            catch (SignatureException e)
            {
                throw new IOException("signature problem: " + e);
            }
        }

        public void write(
            int b)
            throws IOException
        {
            try
            {
                sig.update((byte)b);
            }
            catch (SignatureException e)
            {
                throw new IOException("signature problem: " + e);
            }
        }
    }

    private class SignerInf
    {
        PrivateKey      _key;
        X509Certificate _cert;
        String          _digestOID;
        String          _encOID;
        AttributeTable  _sAttr;
        AttributeTable  _unsAttr;
        MessageDigest   _digest;
        Signature       _signature;

        SignerInf(
            PrivateKey      key,
            X509Certificate cert,
            String          digestOID,
            String          encOID,
            AttributeTable  sAttr,
            AttributeTable  unsAttr,
            MessageDigest   digest,
            Signature       signature)
        {
            _key = key;
            _cert = cert;
            _digestOID = digestOID;
            _encOID = encOID;
            _sAttr = sAttr;
            _unsAttr = unsAttr;
            _digest = digest;
            _signature = signature;
        }

        PrivateKey getKey()
        {
            return _key;
        }

        X509Certificate getCertificate()
        {
            return _cert;
        }

        String getDigestAlgOID()
        {
            return _digestOID;
        }

        byte[] getDigestAlgParams()
        {
            return null;
        }

        String getEncryptionAlgOID()
        {
            return _encOID;
        }

        AttributeTable getSignedAttributes()
        {
            return _sAttr;
        }

        AttributeTable getUnsignedAttributes()
        {
            return _unsAttr;
        }
        
        SignerInfo toSignerInfo(
            String  contentType,
            boolean addDefaultAttributes)
            throws IOException, SignatureException, CertificateEncodingException
        {
            AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(
                  new DERObjectIdentifier(this.getDigestAlgOID()), new DERNull());
            AlgorithmIdentifier encAlgId;
            
            if (this.getEncryptionAlgOID().equals(ENCRYPTION_DSA))
            {
                encAlgId = new AlgorithmIdentifier(
                      new DERObjectIdentifier(this.getEncryptionAlgOID()));
            }
            else
            {
                encAlgId = new AlgorithmIdentifier(
                      new DERObjectIdentifier(this.getEncryptionAlgOID()), new DERNull());
            }

            ASN1Set         signedAttr = null;
            ASN1Set         unsignedAttr = null;
            AttributeTable  attr = this.getSignedAttributes();
            byte[]          hash = _digest.digest();

            if (attr != null)
            {
                ASN1EncodableVector  v = new ASN1EncodableVector();

                if (attr.get(CMSAttributes.contentType) == null)
                {
                    v.add(new Attribute(CMSAttributes.contentType,
                                                   new DERSet(new DERObjectIdentifier(contentType.toString()))));
                }
                else
                {
                    v.add(attr.get(CMSAttributes.contentType));
                }

                if (attr.get(CMSAttributes.signingTime) == null)
                {
                    v.add(new Attribute(CMSAttributes.signingTime,
                                           new DERSet(new Time(new Date()))));
                }
                else
                {
                    v.add(attr.get(CMSAttributes.signingTime));
                }

                v.add(new Attribute(CMSAttributes.messageDigest,
                        new DERSet(new DEROctetString(hash))));
                
                Hashtable           ats = attr.toHashtable();
                
                ats.remove(CMSAttributes.contentType);
                ats.remove(CMSAttributes.signingTime);
                ats.remove(CMSAttributes.messageDigest);
                
                Iterator            it = ats.values().iterator();
                
                while (it.hasNext())
                {
                    v.add(Attribute.getInstance(it.next()));
                }
                
                signedAttr = new DERSet(v);
            }
            else
            {
                if (addDefaultAttributes) 
                {
                    ASN1EncodableVector  v = new ASN1EncodableVector();

                    v.add(new Attribute(
                        CMSAttributes.contentType,
                            new DERSet(new DERObjectIdentifier(contentType.toString()))));

                    v.add(new Attribute(
                        CMSAttributes.signingTime,
                            new DERSet(new DERUTCTime(new Date()))));

                    v.add(new Attribute(
                        CMSAttributes.messageDigest,
                            new DERSet(new DEROctetString(hash))));

                    signedAttr = new DERSet(v);
                }
            }

            attr = this.getUnsignedAttributes();

            if (attr != null)
            {
                Hashtable           ats = attr.toHashtable();
                Iterator            it = ats.values().iterator();
                ASN1EncodableVector  v = new ASN1EncodableVector();

                while (it.hasNext())
                {
                    v.add(Attribute.getInstance(it.next()));
                }

                unsignedAttr = new DERSet(v);
            }

            //
            // sig must be composed from the DER encoding.
            //
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
 
            if (signedAttr != null) 
            {
                DEROutputStream         dOut = new DEROutputStream(bOut);
                dOut.writeObject(signedAttr);
            } 
            else
            {
                throw new RuntimeException("signatures without signed attributes not implemented.");
            }

            _signature.update(bOut.toByteArray());

            ASN1OctetString         encDigest = new DEROctetString(_signature.sign());
            X509Certificate         cert = this.getCertificate();
            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getTBSCertificate());
            ASN1InputStream         aIn = new ASN1InputStream(bIn);
            TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(aIn.readObject());
            IssuerAndSerialNumber   encSid = new IssuerAndSerialNumber(tbs.getIssuer(), tbs.getSerialNumber().getValue());

            return new SignerInfo(new SignerIdentifier(encSid), digAlgId,
                        signedAttr, encAlgId, encDigest, unsignedAttr);
        }

    }

    /**
     * base constructor
     */
    public CMSSignedDataStreamGenerator()
    {
    }

    /**
     * Set the underlying string size for encapsulated data
     * 
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
        int bufferSize)
    {
        _bufferSize = bufferSize;
    }
    
    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
       addSigner(key, cert, digestOID, null, null, sigProvider);
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        String        encOID = getEncOID(key, digestOID);
        String        digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
        String        signatureName = digestName + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(encOID);
        Signature     sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, sigProvider);
        MessageDigest dig = CMSSignedHelper.INSTANCE.getDigestInstance(digestName, sigProvider);
 
        sig.initSign(key);

        _signerInfs.add(new SignerInf(key, cert, digestOID, encOID, signedAttr, unsignedAttr, dig, sig));
        _digests.add(dig);
    }

    /**
     * Add a store of precalculated signers to the generator.
     * 
     * @param signerStore
     */
    public void addSigners(
        SignerInformationStore    signerStore)
    {
        Iterator    it = signerStore.getSigners().iterator();
        
        while (it.hasNext())
        {
            _signers.add(it.next());
        }
    }
    
    /**
     * add the certificates and CRLs contained in the given CertStore
     * to the pool that will be included in the encoded signature block.
     * <p>
     * Note: this assumes the CertStore will support null in the get
     * methods.
     */
    public void addCertificatesAndCRLs(
        CertStore               certStore)
        throws CertStoreException, CMSException
    {
        //
        // divide up the certs and crls.
        //
        try
        {
            Iterator  it = certStore.getCertificates(null).iterator();

            while (it.hasNext())
            {
                X509Certificate         c = (X509Certificate)it.next();

                _certs.add(new X509CertificateStructure(
                                        (ASN1Sequence)makeObj(c.getEncoded())));
            }
        }
        catch (IOException e)
        {
            throw new CMSException("error processing certs", e);
        }
        catch (CertificateEncodingException e)
        {
            throw new CMSException("error encoding certs", e);
        }

        try
        {
            Iterator    it = certStore.getCRLs(null).iterator();

            while (it.hasNext())
            {
                X509CRL                 c = (X509CRL)it.next();

                _crls.add(new CertificateList(
                                        (ASN1Sequence)makeObj(c.getEncoded())));
            }
        }
        catch (IOException e)
        {
            throw new CMSException("error processing crls", e);
        }
        catch (CRLException e)
        {
            throw new CMSException("error encoding crls", e);
        }
    }

    private DERObject makeObj(
        byte[]  encoding)
        throws IOException
    {
        if (encoding == null)
        {
            return null;
        }

        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream         aIn = new ASN1InputStream(bIn);

        return aIn.readObject();
    }

    private AlgorithmIdentifier makeAlgId(
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

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider.
     */
    public OutputStream open(
        OutputStream out)
        throws IOException
    {
        return open(out, false);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     */
    public OutputStream open(
        OutputStream out,
        boolean      encapsulate)
        throws IOException
    {
        return open(out, DATA, encapsulate);
    }
    
    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     */
    public OutputStream open(
        OutputStream out,
        String       signedContentType,
        boolean      encapsulate)
        throws IOException
    {
        //
        // ContentInfo
        //
        BerSequenceGenerator sGen = new BerSequenceGenerator(out);
        
        sGen.addObject(new Asn1ObjectIdentifier(CMSObjectIdentifiers.signedData.getId()));
        
        //
        // Signed Data
        //
        BerSequenceGenerator sigGen = new BerSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        
        sigGen.addObject(getVersion(signedContentType));
        
        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        
        //
        // add the precalculated SignerInfo digest algorithms.
        //
        Iterator            it = _signers.iterator();
        
        while (it.hasNext())
        {
            SignerInformation        signer = (SignerInformation)it.next();
            AlgorithmIdentifier     digAlgId;

            digAlgId = makeAlgId(signer.getDigestAlgOID(), signer.getDigestAlgParams());

            digestAlgs.add(digAlgId);
        }
        
        //
        // add the new digests
        //
        it = _signerInfs.iterator();

        while (it.hasNext())
        {
            SignerInf           signer = (SignerInf)it.next();
            AlgorithmIdentifier digAlgId;

            digAlgId = makeAlgId(signer.getDigestAlgOID(), signer.getDigestAlgParams());

            digestAlgs.add(digAlgId);
        }
        
        sigGen.getRawOutputStream().write(new DERSet(digestAlgs).getEncoded());
        
        BerSequenceGenerator eiGen = new BerSequenceGenerator(sigGen.getRawOutputStream());
        
        eiGen.addObject(new Asn1ObjectIdentifier(signedContentType));
        
        OutputStream digStream;
        
        if (encapsulate)
        {
            BerOctetStringGenerator octGen = new BerOctetStringGenerator(eiGen.getRawOutputStream(), 0, true);
        
            if (_bufferSize != 0)
            {
                digStream = octGen.getOctetOutputStream(new byte[_bufferSize]);
            }
            else
            {
                digStream = octGen.getOctetOutputStream();
            }
        }
        else
        {
            digStream = new NullOutputStream();
        }
        
        it = _digests.iterator();
        
        while (it.hasNext())
        {
            digStream = new DigestOutputStream(digStream, (MessageDigest)it.next());
        }
        
        return new CmsSignedDataOutputStream(digStream, signedContentType, sGen, sigGen, eiGen);
    }
    
    private Asn1Integer getVersion(
        String signedContentType)
    {
        int v = 0;
        // RFC3852, section 5.1:
        // IF ((certificates is present) AND
        //    (any certificates with a type of other are present)) OR
        //    ((crls is present) AND
        //    (any crls with a type of other are present))
        // THEN version MUST be 5
        // ELSE
        //    IF (certificates is present) AND
        //       (any version 2 attribute certificates are present)
        //    THEN version MUST be 4
        //    ELSE
        //       IF ((certificates is present) AND
        //          (any version 1 attribute certificates are present)) OR
        //          (any SignerInfo structures are version 3) OR
        //          (encapContentInfo eContentType is other than id-data)
        //       THEN version MUST be 3
        //       ELSE version MUST be 1
        //
        if (anyCertHasTypeOther() || anyCrlHasTypeOther())
        {
            v = 5;
        }
        else if (anyCertHasV2Attribute())
        {
            v = 4;
        }
        else if (anyCertHasV1Attribute() || /* useV3SignerInfo || */ !signedContentType.equals(DATA))
        {
            v = 3;
        }
        else
        {
            v = 1;
        }
        return new Asn1Integer(v);
    }

    private boolean anyCertHasTypeOther()
    {
        // TODO
        return false;
    }

    private boolean anyCertHasV1Attribute()
    {
        // TODO
        return false;
    }

    private boolean anyCertHasV2Attribute()
    {
        // TODO
        return false;
    }

    private boolean anyCrlHasTypeOther()
    {
        // TODO
        return false;
    }

    private class NullOutputStream
        extends OutputStream
    {
        public void write(int b) throws IOException
        {
            // do nothing
        }
    }
    
    private class CmsSignedDataOutputStream
        extends OutputStream
    {
        private OutputStream         _out;
        private String               _contentOID;
        private BerSequenceGenerator _sGen;
        private BerSequenceGenerator _sigGen;
        private BerSequenceGenerator _eiGen;

        public CmsSignedDataOutputStream(
            OutputStream         out,
            String               contentOID,
            BerSequenceGenerator sGen, 
            BerSequenceGenerator sigGen,
            BerSequenceGenerator eiGen)
        {
            _out = out;
            _contentOID = contentOID;
            _sGen = sGen;
            _sigGen = sigGen;
            _eiGen = eiGen;
        }

        public void write(
            int b)
            throws IOException
        {
            _out.write(b);
        }
        
        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            _out.write(bytes, off, len);
        }
        
        public void write(
            byte[] bytes)
            throws IOException
        {
            _out.write(bytes);
        }
        
        public void close()
            throws IOException
        {
            _out.close();
            _eiGen.close();
            
            if (_certs.size() != 0)
            {
                ASN1EncodableVector  v = new ASN1EncodableVector();

                Iterator it = _certs.iterator();
                while (it.hasNext())
                {
                    v.add((DEREncodable)it.next());
                }

                _sigGen.getRawOutputStream().write(new DERTaggedObject(false, 0, new DERSet(v)).getEncoded());
            }


            if (_crls.size() != 0)
            {
                ASN1EncodableVector  v = new ASN1EncodableVector();

                Iterator it = _crls.iterator();
                while (it.hasNext())
                {
                    v.add((DEREncodable)it.next());
                }

                _sigGen.getRawOutputStream().write(new DERTaggedObject(false, 1, new DERSet(v)).getEncoded());
            }
            
            //
            // add the precalculated SignerInfo objects.
            //
            ASN1EncodableVector signerInfos = new ASN1EncodableVector();
            Iterator            it = _signers.iterator();
            
            while (it.hasNext())
            {
                SignerInformation        signer = (SignerInformation)it.next();

                signerInfos.add(signer.toSignerInfo());
            }
            
            //
            // add the SignerInfo objects
            //
            it = _signerInfs.iterator();

            while (it.hasNext())
            {
                SignerInf               signer = (SignerInf)it.next();

                try
                {
                    signerInfos.add(signer.toSignerInfo(_contentOID, true));
                }
                catch (IOException e)
                {
                    throw new IOException("encoding error." + e);
                }
                catch (SignatureException e)
                {
                    throw new IOException("error creating signature." + e);
                }
                catch (CertificateEncodingException e)
                {
                    throw new IOException("error creating sid." + e);
                }
            }
            
            _sigGen.getRawOutputStream().write(new DERSet(signerInfos).getEncoded());

            _sigGen.close();
            _sGen.close();
        }
    }
}
