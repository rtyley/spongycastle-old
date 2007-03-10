package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
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
 * general class for generating a pkcs7-signature message.
 * <p>
 * A simple example of usage.
 *
 * <pre>
 *      CertStore               certs...
 *      CMSSignedDataGenerator    gen = new CMSSignedDataGenerator();
 *
 *      gen.addSigner(privKey, cert, CMSSignedGenerator.DIGEST_SHA1);
 *      gen.addCertificatesAndCRLs(certs);
 *
 *      CMSSignedData           data = gen.generate(content, "BC");
 * </pre>
 */
public class CMSSignedDataGenerator
    extends CMSSignedGenerator
{
    List                        signerInfs = new ArrayList();

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
        PrivateKey                  key;
        X509Certificate             cert;
        String                      digestOID;
        String                      encOID;
        CMSAttributeTableGenerator  sAttr;
        CMSAttributeTableGenerator  unsAttr;
        AttributeTable              baseSignedTable;

        SignerInf(
            PrivateKey      key,
            X509Certificate cert,
            String          digestOID,
            String          encOID)
        {
            this.key = key;
            this.cert = cert;
            this.digestOID = digestOID;
            this.encOID = encOID;
        }

        SignerInf(
            PrivateKey                 key,
            X509Certificate            cert,
            String                     digestOID,
            String                     encOID,
            CMSAttributeTableGenerator sAttr,
            CMSAttributeTableGenerator unsAttr,
            AttributeTable             baseSigneTable)
        {
            this.key = key;
            this.cert = cert;
            this.digestOID = digestOID;
            this.encOID = encOID;
            this.sAttr = sAttr;
            this.unsAttr = unsAttr;
            this.baseSignedTable = baseSigneTable;
        }

        PrivateKey getKey()
        {
            return key;
        }

        X509Certificate getCertificate()
        {
            return cert;
        }

        String getDigestAlgOID()
        {
            return digestOID;
        }

        byte[] getDigestAlgParams()
        {
            return null;
        }

        String getEncryptionAlgOID()
        {
            return encOID;
        }

        CMSAttributeTableGenerator getSignedAttributes()
        {
            return sAttr;
        }

        CMSAttributeTableGenerator getUnsignedAttributes()
        {
            return unsAttr;
        }   

        SignerInfo toSignerInfo(
            DERObjectIdentifier contentType,
            CMSProcessable      content,
            String              sigProvider,
            boolean             addDefaultAttributes)
            throws IOException, SignatureException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, CertificateEncodingException, CMSException
        {
            AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(
                  new DERObjectIdentifier(this.getDigestAlgOID()), new DERNull());
            AlgorithmIdentifier encAlgId = getEncAlgorithmIdentifier(this.getEncryptionAlgOID());
            String              digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
            String              signatureName = digestName + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(encOID);
            Signature           sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, sigProvider);
            MessageDigest       dig = CMSSignedHelper.INSTANCE.getDigestInstance(digestName, sigProvider);               

            byte[]      hash = null;

            if (content != null)
            {
                content.write(new DigOutputStream(dig));

                hash = dig.digest();

                _digests.put(digestOID, hash.clone());
            }

            AttributeTable signed;

            if (addDefaultAttributes)
            {
                Map parameters = getBaseParameters(contentType, digAlgId, hash);
                signed = (sAttr != null) ? sAttr.getAttributes(Collections.unmodifiableMap(parameters)) : null;
            }
            else
            {
                signed = baseSignedTable;
            }

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
                content.write(bOut);
            }

            sig.initSign(key);

            sig.update(bOut.toByteArray());

            ASN1OctetString         encDigest = new DEROctetString(sig.sign());

            Map parameters = getBaseParameters(contentType, digAlgId, hash);
            parameters.put(CMSAttributeTableGenerator.SIGNATURE, encDigest.getOctets().clone());

            AttributeTable unsigned = (unsAttr != null) ? unsAttr.getAttributes(Collections.unmodifiableMap(parameters)) : null;

            ASN1Set unsignedAttr = getAttributeSet(unsigned);

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
    public CMSSignedDataGenerator()
    {
    }
    
    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID)
        throws IllegalArgumentException
    {
        String  encOID = getEncOID(key, digestOID);

        signerInfs.add(new SignerInf(key, cert, digestOID, encOID, new DefaultSignedAttributeTableGenerator(), null, null));
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        String  encOID = getEncOID(key, digestOID);

        signerInfs.add(new SignerInf(key, cert, digestOID, encOID, new DefaultSignedAttributeTableGenerator(signedAttr), new SimpleAttributeTableGenerator(unsignedAttr), signedAttr));
    }

    /**
     * add a signer with extra signed/unsigned attributes based on generators.
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen)
        throws IllegalArgumentException
    {
        String  encOID = getEncOID(key, digestOID);

        signerInfs.add(new SignerInf(key, cert, digestOID, encOID, signedAttrGen, unsignedAttrGen, null));
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
    public CMSSignedData generate(
        CMSProcessable content,
        String         sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(content, false, sigProvider);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     */
    public CMSSignedData generate(
        String          signedContentType,
        CMSProcessable  content,
        boolean         encapsulate,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(signedContentType, content, encapsulate, sigProvider, true);
    }
    
    /**
     * Similar method to the other generate methods. The additional argument
     * addDefaultAttributes indicates whether or not a default set of signed attributes
     * need to be added automatically. If the argument is set to false, no
     * attributes will get added at all. 
     */
    public CMSSignedData generate(
        String                  signedContentType,
        CMSProcessable          content,
        boolean                 encapsulate,
        String                  sigProvider,
        boolean                 addDefaultAttributes)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        ASN1EncodableVector  signerInfos = new ASN1EncodableVector();

        DERObjectIdentifier      contentTypeOID = new DERObjectIdentifier(signedContentType);

        _digests.clear();  // clear the current preserved digest state

        //
        // add the precalculated SignerInfo objects.
        //
        Iterator            it = _signers.iterator();
        
        while (it.hasNext())
        {
            SignerInformation        signer = (SignerInformation)it.next();
            AlgorithmIdentifier     digAlgId;
            
            try
            {
                digAlgId = makeAlgId(signer.getDigestAlgOID(),
                                                       signer.getDigestAlgParams());
            }
            catch (IOException e)
            {
                throw new CMSException("encoding error.", e);
            }

           digestAlgs.add(digAlgId);

           signerInfos.add(signer.toSignerInfo());
        }
        
        //
        // add the SignerInfo objects
        //
        it = signerInfs.iterator();

        while (it.hasNext())
        {
            SignerInf                   signer = (SignerInf)it.next();
            AlgorithmIdentifier     digAlgId;

            try
            {
                digAlgId = makeAlgId(signer.getDigestAlgOID(),
                                            signer.getDigestAlgParams());

                digestAlgs.add(digAlgId);

                signerInfos.add(signer.toSignerInfo(contentTypeOID, content, sigProvider, addDefaultAttributes));
            }
            catch (IOException e)
            {
                throw new CMSException("encoding error.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CMSException("key inappropriate for signature.", e);
            }
            catch (SignatureException e)
            {
                throw new CMSException("error creating signature.", e);
            }
            catch (CertificateEncodingException e)
            {
                throw new CMSException("error creating sid.", e);
            }
        }

        ASN1Set certificates = null;

        if (_certs.size() != 0)
        {
            certificates = CMSUtils.createBerSetFromList(_certs);
        }

        ASN1Set certrevlist = null;

        if (_crls.size() != 0)
        {
            certrevlist = CMSUtils.createBerSetFromList(_crls);
        }

        ContentInfo    encInfo;
        
        if (encapsulate)
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

            try
            {
                content.write(bOut);
            }
            catch (IOException e)
            {
                throw new CMSException("encapsulation error.", e);
            }

            ASN1OctetString  octs = new BERConstructedOctetString(
                                                    bOut.toByteArray());

            encInfo = new ContentInfo(contentTypeOID, octs);
        }
        else
        {
            encInfo = new ContentInfo(contentTypeOID, null);
        }

        SignedData  sd = new SignedData(
                                 new DERSet(digestAlgs),
                                 encInfo, 
                                 certificates, 
                                 certrevlist, 
                                 new DERSet(signerInfos));

        ContentInfo contentInfo = new ContentInfo(
                PKCSObjectIdentifiers.signedData, sd);

        return new CMSSignedData(content, contentInfo);
    }
    
    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     */
    public CMSSignedData generate(
        CMSProcessable  content,
        boolean         encapsulate,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return this.generate(DATA, content, encapsulate, sigProvider);
    }
}

