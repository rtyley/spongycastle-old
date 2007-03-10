package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BEROctetStringGenerator;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;

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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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
    private List _signerInfs = new ArrayList();
    private List _messageDigests = new ArrayList();
    private int  _bufferSize;

    private class SignerInf
    {
        PrivateKey                  _key;
        X509Certificate             _cert;
        String                      _digestOID;
        String                      _encOID;
        CMSAttributeTableGenerator  _sAttr;
        CMSAttributeTableGenerator  _unsAttr;
        MessageDigest               _digest;
        Signature                   _signature;

        SignerInf(
            PrivateKey                  key,
            X509Certificate             cert,
            String                      digestOID,
            String                      encOID,
            CMSAttributeTableGenerator  sAttr,
            CMSAttributeTableGenerator  unsAttr,
            MessageDigest               digest,
            Signature                   signature)
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
        
        SignerInfo toSignerInfo(
            DERObjectIdentifier  contentType)
            throws IOException, SignatureException, CertificateEncodingException
        {
            AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(
                  new DERObjectIdentifier(this.getDigestAlgOID()), new DERNull());
            AlgorithmIdentifier encAlgId = getEncAlgorithmIdentifier(this.getEncryptionAlgOID());

            byte[]          hash = _digest.digest();

            _digests.put(_digestOID, hash.clone());

            Map  parameters = getBaseParameters(contentType, digAlgId, hash);

            AttributeTable signed = (_sAttr != null) ? _sAttr.getAttributes(Collections.unmodifiableMap(parameters)) : null;

            ASN1Set signedAttr = getAttributeSet(signed);

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

            parameters = getBaseParameters(contentType, digAlgId, hash);
            parameters.put(CMSAttributeTableGenerator.SIGNATURE, encDigest.getOctets().clone());

            AttributeTable unsigned = (_unsAttr != null) ? _unsAttr.getAttributes(Collections.unmodifiableMap(parameters)) : null;

            ASN1Set unsignedAttr = getAttributeSet(unsigned);

            X509Certificate         cert = this.getCertificate();
            ASN1InputStream         aIn = new ASN1InputStream(cert.getTBSCertificate());
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
       addSigner(key, cert, digestOID, new DefaultSignedAttributeTableGenerator(), (CMSAttributeTableGenerator)null, sigProvider);
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
        addSigner(key, cert, digestOID,
            new DefaultSignedAttributeTableGenerator(signedAttr), new SimpleAttributeTableGenerator(unsignedAttr), sigProvider);
    }

    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGenerator,
        CMSAttributeTableGenerator  unsignedAttrGenerator,
        String                      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        String        encOID = getEncOID(key, digestOID);
        String        digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
        String        signatureName = digestName + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(encOID);
        Signature     sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, sigProvider);
        MessageDigest dig = CMSSignedHelper.INSTANCE.getDigestInstance(digestName, sigProvider);

        sig.initSign(key);

        _signerInfs.add(new SignerInf(key, cert, digestOID, encOID, signedAttrGenerator, unsignedAttrGenerator, dig, sig));
        _messageDigests.add(dig);
    }

    private DERObject makeObj(
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
        BERSequenceGenerator sGen = new BERSequenceGenerator(out);
        
        sGen.addObject(CMSObjectIdentifiers.signedData);
        
        //
        // Signed Data
        //
        BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);
        
        sigGen.addObject(calculateVersion(signedContentType));
        
        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        
        //
        // add the precalculated SignerInfo digest algorithms.
        //
        for (Iterator it = _signers.iterator(); it.hasNext();)
        {
            SignerInformation        signer = (SignerInformation)it.next();
            AlgorithmIdentifier     digAlgId;

            digAlgId = makeAlgId(signer.getDigestAlgOID(), signer.getDigestAlgParams());

            digestAlgs.add(digAlgId);
        }
        
        //
        // add the new digests
        //
        for (Iterator it = _signerInfs.iterator(); it.hasNext();)
        {
            SignerInf           signer = (SignerInf)it.next();
            AlgorithmIdentifier digAlgId;

            digAlgId = makeAlgId(signer.getDigestAlgOID(), signer.getDigestAlgParams());

            digestAlgs.add(digAlgId);
        }
        
        sigGen.getRawOutputStream().write(new DERSet(digestAlgs).getEncoded());
        
        BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());
        
        eiGen.addObject(new DERObjectIdentifier(signedContentType));
        
        OutputStream digStream;
        
        if (encapsulate)
        {
            BEROctetStringGenerator octGen = new BEROctetStringGenerator(eiGen.getRawOutputStream(), 0, true);
            
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
        
        for (Iterator it = _messageDigests.iterator(); it.hasNext();)
        {
            digStream = new DigestOutputStream(digStream, (MessageDigest)it.next());
        }
        
        return new CmsSignedDataOutputStream(digStream, signedContentType, sGen, sigGen, eiGen);
    }

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
    private DERInteger calculateVersion(
        String contentOid)
    {
        boolean otherCert = false;
        boolean otherCrl = false;
        boolean attrCertV1Found = false;
        boolean attrCertV2Found = false;

        if (_certs != null)
        {
            for (Iterator it = _certs.iterator(); it.hasNext();)
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tagged = (ASN1TaggedObject)obj;

                    if (tagged.getTagNo() == 1)
                    {
                        attrCertV1Found = true;
                    }
                    else if (tagged.getTagNo() == 2)
                    {
                        attrCertV2Found = true;
                    }
                    else if (tagged.getTagNo() == 3)
                    {
                        otherCert = true;
                    }
                }
            }
        }

        if (otherCert)
        {
            return new DERInteger(5);
        }

        if (_crls != null && !otherCert)         // no need to check if otherCert is true
        {
            for (Iterator it = _crls.iterator(); it.hasNext();)
            {
                Object obj = it.next();
                if (obj instanceof ASN1TaggedObject)
                {
                    otherCrl = true;
                }
            }
        }

        if (otherCrl)
        {
            return new DERInteger(5);
        }

        if (attrCertV2Found)
        {
            return new DERInteger(4);
        }

        if (attrCertV1Found)
        {
            return new DERInteger(3);
        }

        if (contentOid.equals(DATA))
        {
            if (checkForVersion3(_signers))
            {
                return new DERInteger(3);
            }
            else
            {
                return new DERInteger(1);
            }
        }
        else
        {
            return new DERInteger(3);
        }
    }

    private boolean checkForVersion3(List signerInfos)
    {
        for (Iterator it = signerInfos.iterator(); it.hasNext();)
        {
            SignerInfo s = SignerInfo.getInstance(((SignerInformation)it.next()).toSignerInfo());

            if (s.getVersion().getValue().intValue() == 3)
            {
                return true;
            }
        }

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
        private DERObjectIdentifier  _contentOID;
        private BERSequenceGenerator _sGen;
        private BERSequenceGenerator _sigGen;
        private BERSequenceGenerator _eiGen;

        public CmsSignedDataOutputStream(
            OutputStream         out,
            String               contentOID,
            BERSequenceGenerator sGen,
            BERSequenceGenerator sigGen,
            BERSequenceGenerator eiGen)
        {
            _out = out;
            _contentOID = new DERObjectIdentifier(contentOID);
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

            _digests.clear();    // clear the current preserved digest state

            if (_certs.size() != 0)
            {
                ASN1Set certs = CMSUtils.createBerSetFromList(_certs);

                _sigGen.getRawOutputStream().write(new BERTaggedObject(false, 0, certs).getEncoded());
            }

            if (_crls.size() != 0)
            {
                ASN1Set crls = CMSUtils.createBerSetFromList(_crls);

                _sigGen.getRawOutputStream().write(new BERTaggedObject(false, 1, crls).getEncoded());
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
                    signerInfos.add(signer.toSignerInfo(_contentOID));
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
