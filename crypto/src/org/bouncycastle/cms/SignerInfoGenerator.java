package org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;

class SignerInfoGenerator
{
    private static final Set RSA_PKCS1d5 = new HashSet();

    static
    {
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.md2WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.md4WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.md5WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.sha224WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.sha384WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.sha512WithRSAEncryption);
        RSA_PKCS1d5.add(OIWObjectIdentifiers.md4WithRSAEncryption);
        RSA_PKCS1d5.add(OIWObjectIdentifiers.md4WithRSA);
        RSA_PKCS1d5.add(OIWObjectIdentifiers.md5WithRSA);
        RSA_PKCS1d5.add(OIWObjectIdentifiers.sha1WithRSA);
        RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
    }

    private final SignerIdentifier signerIdentifier;
    private final CMSAttributeTableGenerator sAttrGen;
    private final CMSAttributeTableGenerator unsAttrGen;
    private final ContentSigner signer;
    private final DigestCalculator digester;

    SignerInfoGenerator(
        SignerIdentifier signerIdentifier,
        ContentSigner signer)
    {
        this(signerIdentifier, signer, null, null, null);
    }

    SignerInfoGenerator(
        SignerIdentifier signerIdentifier,
        ContentSigner signer,
        org.bouncycastle.operator.DigestCalculator digester)
    {
        this(signerIdentifier, signer, digester, new DefaultSignedAttributeTableGenerator(), null);
    }

    SignerInfoGenerator(
        SignerIdentifier signerIdentifier,
        ContentSigner signer,
        DigestCalculator digester,
        CMSAttributeTableGenerator sAttrGen,
        CMSAttributeTableGenerator unsAttrGen)
    {
        this.signerIdentifier = signerIdentifier;
        this.signer = signer;
        this.digester = digester;
        this.sAttrGen = sAttrGen;
        this.unsAttrGen = unsAttrGen;
    }

    public OutputStream getCalculatingOutputStream()
    {
        if (digester != null)
        {
            return digester.getOutputStream();
        }
        else
        {
            return signer.getOutputStream();
        }
    }

    public SignerInfo generate(ASN1ObjectIdentifier contentType)
        throws CMSStreamException
    {
        try
        {
            /* RFC 3852 5.4
             * The result of the message digest calculation process depends on
             * whether the signedAttrs field is present.  When the field is absent,
             * the result is just the message digest of the content as described
             *
             * above.  When the field is present, however, the result is the message
             * digest of the complete DER encoding of the SignedAttrs value
             * contained in the signedAttrs field.
             */
            ASN1Set signedAttr = null;
            byte[] calculatedDigest = null;

            if (digester != null)
            {
                calculatedDigest = digester.getDigest();
                Map parameters = getBaseParameters(contentType, digester.getAlgorithmIdentifier(), calculatedDigest);
                AttributeTable signed = sAttrGen.getAttributes(Collections.unmodifiableMap(parameters));

                // TODO Handle countersignatures (see CMSSignedDataGenerator)

                signedAttr = getAttributeSet(signed);

                // sig must be composed from the DER encoding.
                OutputStream sOut = signer.getOutputStream();

                sOut.write(signedAttr.getEncoded(ASN1Encodable.DER));

                sOut.close();
            }

            byte[] sigBytes = signer.getSignature();

            ASN1Set unsignedAttr = null;
            if (unsAttrGen != null)
            {
                Map parameters = getBaseParameters(contentType, digester.getAlgorithmIdentifier(), calculatedDigest);
                parameters.put(CMSAttributeTableGenerator.SIGNATURE, sigBytes.clone());

                AttributeTable unsigned = unsAttrGen.getAttributes(Collections.unmodifiableMap(parameters));

                unsignedAttr = getAttributeSet(unsigned);
            }

            AlgorithmIdentifier digestEncryptionAlgorithm = getSignatureAlgorithm(signer.getAlgorithmIdentifier());

            return new SignerInfo(signerIdentifier, null, // digester.getAlgorithmIdentifier(),
                signedAttr, digestEncryptionAlgorithm, new DEROctetString(sigBytes), unsignedAttr);
        }
        catch (IOException e)
        {
            throw new CMSStreamException("encoding error.", e);
        }
    }

    private ASN1Set getAttributeSet(
        AttributeTable attr)
    {
        if (attr != null)
        {
            return new DERSet(attr.toASN1EncodableVector());
        }

        return null;
    }

    private Map getBaseParameters(DERObjectIdentifier contentType, AlgorithmIdentifier digAlgId, byte[] hash)
    {
        Map param = new HashMap();
        param.put(CMSAttributeTableGenerator.CONTENT_TYPE, contentType);
        param.put(CMSAttributeTableGenerator.DIGEST_ALGORITHM_IDENTIFIER, digAlgId);
        param.put(CMSAttributeTableGenerator.DIGEST,  hash.clone());
        return param;
    }

    protected AlgorithmIdentifier getSignatureAlgorithm(AlgorithmIdentifier sigAlgID)
        throws IOException
    {
        // RFC3370 section 3.2
        if (RSA_PKCS1d5.contains(sigAlgID.getAlgorithm()))
        {
            return new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        }

        return sigAlgID;
    }
}
