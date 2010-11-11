package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

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

    private class SignerInf
    {
        private final PrivateKey                  key;
        private final SignerIdentifier            signerIdentifier;
        private final String                      digestOID;
        private final String                      encOID;
        private final CMSAttributeTableGenerator  sAttr;
        private final CMSAttributeTableGenerator  unsAttr;
        private final AttributeTable              baseSignedTable;

        SignerInf(
            PrivateKey                 key,
            SignerIdentifier           signerIdentifier,
            String                     digestOID,
            String                     encOID,
            CMSAttributeTableGenerator sAttr,
            CMSAttributeTableGenerator unsAttr,
            AttributeTable             baseSignedTable)
        {
            this.key = key;
            this.signerIdentifier = signerIdentifier;
            this.digestOID = digestOID;
            this.encOID = encOID;
            this.sAttr = sAttr;
            this.unsAttr = unsAttr;
            this.baseSignedTable = baseSignedTable;
        }

        AlgorithmIdentifier getDigestAlgorithmID()
        {
            return new AlgorithmIdentifier(new DERObjectIdentifier(digestOID), new DERNull());
        }

        SignerInfo toSignerInfo(
            DERObjectIdentifier contentType,
            CMSProcessable      content,
            SecureRandom        random,
            Provider            sigProvider,
            boolean             addDefaultAttributes,
            boolean             isCounterSignature)
            throws IOException, SignatureException, InvalidKeyException, NoSuchAlgorithmException, CertificateEncodingException, CMSException
        {
            AlgorithmIdentifier digAlgId = getDigestAlgorithmID();
            String              digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
            String              signatureName = digestName + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(encOID);
            Signature           sig;
            MessageDigest       dig;
            try
            {
                sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, sigProvider);
                dig = CMSSignedHelper.INSTANCE.getDigestInstance(digestName, sigProvider);               
            }
            catch (NoSuchProviderException e)
            {
                throw new CMSException("cannot access provider.", e);
            }
            AlgorithmIdentifier encAlgId = getEncAlgorithmIdentifier(encOID, sig);

            if (content != null)
            {
                content.write(new DigOutputStream(dig));
            }

            byte[] hash = dig.digest();
            digests.put(digestOID, hash.clone());

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

            ASN1Set signedAttr = null;
            byte[] tmp;
            if (signed != null)
            {
                if (isCounterSignature)
                {
                    Hashtable tmpSigned = signed.toHashtable();
                    tmpSigned.remove(CMSAttributes.contentType);
                    signed = new AttributeTable(tmpSigned);
                }

                // TODO Validate proposed signed attributes

                signedAttr = getAttributeSet(signed);

                // sig must be composed from the DER encoding.
                tmp = signedAttr.getEncoded(ASN1Encodable.DER);
            }
            else
            {
                // TODO Use raw signature of the hash value instead
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                if (content != null)
                {
                    content.write(bOut);
                }
                tmp = bOut.toByteArray();
            }

            sig.initSign(key, random);
            sig.update(tmp);
            byte[] sigBytes = sig.sign();

            ASN1Set unsignedAttr = null;
            if (unsAttr != null)
            {
                Map parameters = getBaseParameters(contentType, digAlgId, hash);
                parameters.put(CMSAttributeTableGenerator.SIGNATURE, sigBytes.clone());

                AttributeTable unsigned = unsAttr.getAttributes(Collections.unmodifiableMap(parameters));

                // TODO Validate proposed unsigned attributes

                unsignedAttr = getAttributeSet(unsigned);
            }

            return new SignerInfo(signerIdentifier, digAlgId,
                signedAttr, encAlgId, new DEROctetString(sigBytes), unsignedAttr);
        }
    }
    
    /**
     * base constructor
     */
    public CMSSignedDataGenerator()
    {
    }

    /**
     * constructor allowing specific source of randomness
     * @param rand instance of SecureRandom to use
     */
    public CMSSignedDataGenerator(
        SecureRandom rand)
    {
        super(rand);
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     *
     * @param key signing key to use
     * @param cert certificate containing corresponding public key
     * @param digestOID digest algorithm OID
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID)
        throws IllegalArgumentException
    {
        addSigner(key, cert, getEncOID(key, digestOID), digestOID);
    }

    /**
     * add a signer, specifying the digest encryption algorithm to use - no attributes other than the default ones will be
     * provided here.
     *
     * @param key signing key to use
     * @param cert certificate containing corresponding public key
     * @param encryptionOID digest encryption algorithm OID
     * @param digestOID digest algorithm OID
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID)
        throws IllegalArgumentException
    {
        signerInfs.add(new SignerInf(key, getSignerIdentifier(cert), digestOID, encryptionOID, new DefaultSignedAttributeTableGenerator(), null, null));
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID)
        throws IllegalArgumentException
    {
        addSigner(key, subjectKeyID, getEncOID(key, digestOID), digestOID);
    }

    /**
     * add a signer, specifying the digest encryption algorithm to use - no attributes other than the default ones will be
     * provided here.
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          encryptionOID,
        String          digestOID)
        throws IllegalArgumentException
    {
        signerInfs.add(new SignerInf(key, getSignerIdentifier(subjectKeyID), digestOID, encryptionOID, new DefaultSignedAttributeTableGenerator(), null, null));
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     *
     * @param key signing key to use
     * @param cert certificate containing corresponding public key
     * @param digestOID digest algorithm OID
     * @param signedAttr table of attributes to be included in signature
     * @param unsignedAttr table of attributes to be included as unsigned
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        addSigner(key, cert, getEncOID(key, digestOID), digestOID, signedAttr, unsignedAttr);
    }

    /**
     * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes.
     *
     * @param key signing key to use
     * @param cert certificate containing corresponding public key
     * @param encryptionOID digest encryption algorithm OID
     * @param digestOID digest algorithm OID
     * @param signedAttr table of attributes to be included in signature
     * @param unsignedAttr table of attributes to be included as unsigned
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          encryptionOID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        signerInfs.add(new SignerInf(key, getSignerIdentifier(cert), digestOID, encryptionOID, new DefaultSignedAttributeTableGenerator(signedAttr), new SimpleAttributeTableGenerator(unsignedAttr), signedAttr));
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     *
     * @param key signing key to use
     * @param subjectKeyID subjectKeyID of corresponding public key
     * @param digestOID digest algorithm OID
     * @param signedAttr table of attributes to be included in signature
     * @param unsignedAttr table of attributes to be included as unsigned
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        addSigner(key, subjectKeyID, digestOID, getEncOID(key, digestOID), new DefaultSignedAttributeTableGenerator(signedAttr), new SimpleAttributeTableGenerator(unsignedAttr));
    }

    /**
     * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes.
     *
     * @param key signing key to use
     * @param subjectKeyID subjectKeyID of corresponding public key
     * @param encryptionOID digest encryption algorithm OID
     * @param digestOID digest algorithm OID
     * @param signedAttr table of attributes to be included in signature
     * @param unsignedAttr table of attributes to be included as unsigned
     */
    public void addSigner(
        PrivateKey      key,
        byte[]          subjectKeyID,
        String          encryptionOID,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        signerInfs.add(new SignerInf(key, getSignerIdentifier(subjectKeyID), digestOID, encryptionOID, new DefaultSignedAttributeTableGenerator(signedAttr), new SimpleAttributeTableGenerator(unsignedAttr), signedAttr));
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
        addSigner(key, cert, getEncOID(key, digestOID), digestOID, signedAttrGen, unsignedAttrGen);
    }

    /**
     * add a signer, specifying the digest encryption algorithm, with extra signed/unsigned attributes based on generators.
     */
    public void addSigner(
        PrivateKey                  key,
        X509Certificate             cert,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen)
        throws IllegalArgumentException
    {
        signerInfs.add(new SignerInf(key, getSignerIdentifier(cert), digestOID, encryptionOID, signedAttrGen, unsignedAttrGen, null));
    }

    /**
     * add a signer with extra signed/unsigned attributes based on generators.
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen)
        throws IllegalArgumentException
    {
        addSigner(key, subjectKeyID, digestOID, getEncOID(key, digestOID), signedAttrGen, unsignedAttrGen);
    }

    /**
     * add a signer, including digest encryption algorithm, with extra signed/unsigned attributes based on generators.
     */
    public void addSigner(
        PrivateKey                  key,
        byte[]                      subjectKeyID,
        String                      encryptionOID,
        String                      digestOID,
        CMSAttributeTableGenerator  signedAttrGen,
        CMSAttributeTableGenerator  unsignedAttrGen)
        throws IllegalArgumentException
    {
        signerInfs.add(new SignerInf(key, getSignerIdentifier(subjectKeyID), digestOID, encryptionOID, signedAttrGen, unsignedAttrGen, null));
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
        return generate(content, CMSUtils.getProvider(sigProvider));
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider.
     */
    public CMSSignedData generate(
        CMSProcessable content,
        Provider       sigProvider)
        throws NoSuchAlgorithmException, CMSException
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
        String          eContentType,
        CMSProcessable  content,
        boolean         encapsulate,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(eContentType, content, encapsulate, CMSUtils.getProvider(sigProvider), true);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     */
    public CMSSignedData generate(
        String          eContentType,
        CMSProcessable  content,
        boolean         encapsulate,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, CMSException
    {
        return generate(eContentType, content, encapsulate, sigProvider, true);
    }

    /**
     * Similar method to the other generate methods. The additional argument
     * addDefaultAttributes indicates whether or not a default set of signed attributes
     * need to be added automatically. If the argument is set to false, no
     * attributes will get added at all.
     */
    public CMSSignedData generate(
        String                  eContentType,
        CMSProcessable          content,
        boolean                 encapsulate,
        String                  sigProvider,
        boolean                 addDefaultAttributes)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(eContentType, content, encapsulate, CMSUtils.getProvider(sigProvider), addDefaultAttributes);
    }

    /**
     * Similar method to the other generate methods. The additional argument
     * addDefaultAttributes indicates whether or not a default set of signed attributes
     * need to be added automatically. If the argument is set to false, no
     * attributes will get added at all. 
     */
    public CMSSignedData generate(
        String                  eContentType,
        CMSProcessable          content,
        boolean                 encapsulate,
        Provider                sigProvider,
        boolean                 addDefaultAttributes)
        throws NoSuchAlgorithmException, CMSException
    {
        // TODO
//        if (signerInfs.isEmpty())
//        {
//            /* RFC 3852 5.2
//             * "In the degenerate case where there are no signers, the
//             * EncapsulatedContentInfo value being "signed" is irrelevant.  In this
//             * case, the content type within the EncapsulatedContentInfo value being
//             * "signed" MUST be id-data (as defined in section 4), and the content
//             * field of the EncapsulatedContentInfo value MUST be omitted."
//             */
//            if (encapsulate)
//            {
//                throw new IllegalArgumentException("no signers, encapsulate must be false");
//            }
//            if (!DATA.equals(eContentType))
//            {
//                throw new IllegalArgumentException("no signers, eContentType must be id-data");
//            }
//        }
//
//        if (!DATA.equals(eContentType))
//        {
//            /* RFC 3852 5.3
//             * [The 'signedAttrs']...
//             * field is optional, but it MUST be present if the content type of
//             * the EncapsulatedContentInfo value being signed is not id-data.
//             */
//            // TODO signedAttrs must be present for all signers
//        }

        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        ASN1EncodableVector  signerInfos = new ASN1EncodableVector();

        digests.clear();  // clear the current preserved digest state

        //
        // add the precalculated SignerInfo objects.
        //
        Iterator            it = _signers.iterator();
        
        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
            digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));
            signerInfos.add(signer.toSignerInfo());
        }
        
        //
        // add the SignerInfo objects
        //
        boolean isCounterSignature = (eContentType == null);

        DERObjectIdentifier contentTypeOID = isCounterSignature
            ?   CMSObjectIdentifiers.data
            :   new DERObjectIdentifier(eContentType);

        it = signerInfs.iterator();

        while (it.hasNext())
        {
            SignerInf signer = (SignerInf)it.next();

            try
            {
                digestAlgs.add(signer.getDigestAlgorithmID());
                signerInfos.add(signer.toSignerInfo(contentTypeOID, content, rand, sigProvider, addDefaultAttributes, isCounterSignature));
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

        if (certs.size() != 0)
        {
            certificates = CMSUtils.createBerSetFromList(certs);
        }

        ASN1Set certrevlist = null;

        if (crls.size() != 0)
        {
            certrevlist = CMSUtils.createBerSetFromList(crls);
        }

        ASN1OctetString octs = null;
        if (encapsulate)
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

            if (content != null)
            {
                try
                {
                    content.write(bOut);
                }
                catch (IOException e)
                {
                    throw new CMSException("encapsulation error.", e);
                }
            }

            octs = new BERConstructedOctetString(bOut.toByteArray());
        }

        ContentInfo encInfo = new ContentInfo(contentTypeOID, octs);

        SignedData  sd = new SignedData(
                                 new DERSet(digestAlgs),
                                 encInfo, 
                                 certificates, 
                                 certrevlist, 
                                 new DERSet(signerInfos));

        ContentInfo contentInfo = new ContentInfo(
            CMSObjectIdentifiers.signedData, sd);

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

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     */
    public CMSSignedData generate(
        CMSProcessable  content,
        boolean         encapsulate,
        Provider        sigProvider)
        throws NoSuchAlgorithmException, CMSException
    {
        return this.generate(DATA, content, encapsulate, sigProvider);
    }

    /**
     * generate a set of one or more SignerInformation objects representing counter signatures on
     * the passed in SignerInformation object.
     *
     * @param signer the signer to be countersigned
     * @param sigProvider the provider to be used for counter signing.
     * @return a store containing the signers.
     */
    public SignerInformationStore generateCounterSigners(SignerInformation signer, Provider sigProvider)
        throws NoSuchAlgorithmException, CMSException
    {
        return this.generate(null, new CMSProcessableByteArray(signer.getSignature()), false, sigProvider).getSignerInfos();
    }

    /**
     * generate a set of one or more SignerInformation objects representing counter signatures on
     * the passed in SignerInformation object.
     *
     * @param signer the signer to be countersigned
     * @param sigProvider the provider to be used for counter signing.
     * @return a store containing the signers.
     */
    public SignerInformationStore generateCounterSigners(SignerInformation signer, String sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return this.generate(null, new CMSProcessableByteArray(signer.getSignature()), false, CMSUtils.getProvider(sigProvider)).getSignerInfos();
    }
}

