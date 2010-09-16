package org.bouncycastle.cms.lw;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.lw.LwContentSignerBuilder;
import org.bouncycastle.operator.lw.LwDigestCalculatorProviderBuilder;

public class LwSignerInfoGeneratorBuilder
{
    private LwContentSignerBuilder contentSignerBuilder;
    private LwDigestCalculatorProviderBuilder digestBuilder;
    private DigestCalculatorProvider digestProvider;
    private boolean directSignature;
    private CMSAttributeTableGenerator signedGen;
    private CMSAttributeTableGenerator unsignedGen;

    public LwSignerInfoGeneratorBuilder(String signatureAlgorithm)
    {
        this.contentSignerBuilder = new LwContentSignerBuilder(signatureAlgorithm);
        this.digestBuilder = new LwDigestCalculatorProviderBuilder();
    }

    public LwSignerInfoGeneratorBuilder(String signatureAlgorithm, DigestCalculatorProvider digestProvider)
    {
        this.contentSignerBuilder = new LwContentSignerBuilder(signatureAlgorithm);
        this.digestProvider = digestProvider;
    }

    /**
     * If the passed in flag is true, the signer signature will be based on the data, not
     * a collection of signed attributes, and no signed attributes will be included.
     *
     * @return the builder object
     */
    public LwSignerInfoGeneratorBuilder setDirectSignature(boolean hasNoSignedAttributes)
    {
        this.directSignature = hasNoSignedAttributes;

        return this;
    }

    public LwSignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
    {
        this.signedGen = signedGen;

        return this;
    }

    public LwSignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
    {
        this.unsignedGen = unsignedGen;

        return this;
    }

    public SignerInfoGenerator build(AsymmetricKeyParameter privateKey, X509CertificateHolder certHolder)
        throws OperatorCreationException
    {
        ContentSigner contentSigner = contentSignerBuilder.build(privateKey);

        SignerIdentifier sigId = new SignerIdentifier(certHolder.getIssuerAndSerialNumber());

        return createGenerator(contentSigner, sigId);
    }

    public SignerInfoGenerator build(AsymmetricKeyParameter privateKey, byte[] keyIdentifier)
        throws OperatorCreationException
    {
        ContentSigner contentSigner = contentSignerBuilder.build(privateKey);

        SignerIdentifier sigId = new SignerIdentifier(new DEROctetString(keyIdentifier));

        return createGenerator(contentSigner, sigId);
    }

    private SignerInfoGenerator createGenerator(ContentSigner contentSigner, SignerIdentifier sigId)
        throws OperatorCreationException
    {
        DigestCalculatorProvider digProvider = digestProvider;

        if (digProvider == null)
        {
            digProvider = digestBuilder.build();
        }

        if (directSignature)
        {
            return new SignerInfoGenerator(sigId, contentSigner, digProvider, true);
        }

        if (signedGen != null || unsignedGen != null)
        {
            return new SignerInfoGenerator(sigId, contentSigner, digProvider, signedGen, unsignedGen);
        }
        
        return new SignerInfoGenerator(sigId, contentSigner, digProvider);
    }
}
