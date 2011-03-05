package org.spongycastle.cms;

import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.cms.SignerIdentifier;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DigestCalculatorProvider;
import org.spongycastle.operator.OperatorCreationException;

public class SignerInfoGeneratorBuilder
{
    private DigestCalculatorProvider digestProvider;
    private boolean directSignature;
    private CMSAttributeTableGenerator signedGen;
    private CMSAttributeTableGenerator unsignedGen;

    public SignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider)
    {
        this.digestProvider = digestProvider;
    }

    /**
     * If the passed in flag is true, the signer signature will be based on the data, not
     * a collection of signed attributes, and no signed attributes will be included.
     *
     * @return the builder object
     */
    public SignerInfoGeneratorBuilder setDirectSignature(boolean hasNoSignedAttributes)
    {
        this.directSignature = hasNoSignedAttributes;

        return this;
    }

    public SignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
    {
        this.signedGen = signedGen;

        return this;
    }

    public SignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
    {
        this.unsignedGen = unsignedGen;

        return this;
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, X509CertificateHolder certHolder)
        throws OperatorCreationException
    {
        SignerIdentifier sigId = new SignerIdentifier(certHolder.getIssuerAndSerialNumber());

        SignerInfoGenerator sigInfoGen = createGenerator(contentSigner, sigId);

        sigInfoGen.setAssociatedCertificate(certHolder);

        return sigInfoGen;
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, byte[] keyIdentifier)
        throws OperatorCreationException
    {
        SignerIdentifier sigId = new SignerIdentifier(new DEROctetString(keyIdentifier));

        return createGenerator(contentSigner, sigId);
    }

    private SignerInfoGenerator createGenerator(ContentSigner contentSigner, SignerIdentifier sigId)
        throws OperatorCreationException
    {
        if (directSignature)
        {
            return new SignerInfoGenerator(sigId, contentSigner, digestProvider, true);
        }

        if (signedGen != null || unsignedGen != null)
        {
            if (signedGen == null)
            {
                signedGen = new DefaultSignedAttributeTableGenerator();
            }

            return new SignerInfoGenerator(sigId, contentSigner, digestProvider, signedGen, unsignedGen);
        }
        
        return new SignerInfoGenerator(sigId, contentSigner, digestProvider);
    }
}
