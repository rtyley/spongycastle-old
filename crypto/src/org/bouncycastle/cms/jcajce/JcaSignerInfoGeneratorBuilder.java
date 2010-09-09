package org.bouncycastle.cms.jcajce;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JcaSignerInfoGeneratorBuilder
{
    private JcaContentSignerBuilder contentSignerBuilder;
    private JcaDigestCalculatorProviderBuilder digestBuilder;
    private DigestCalculatorProvider digestProvider;
    private boolean directSignature;
    private CMSAttributeTableGenerator signedGen;
    private CMSAttributeTableGenerator unsignedGen;

    public JcaSignerInfoGeneratorBuilder(String signatureAlgorithm)
    {
        this.contentSignerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        this.digestBuilder = new JcaDigestCalculatorProviderBuilder();
    }

    public JcaSignerInfoGeneratorBuilder(String signatureAlgorithm, DigestCalculatorProvider digestProvider)
    {
        this.contentSignerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        this.digestProvider = digestProvider;
    }

    public JcaSignerInfoGeneratorBuilder setProvider(Provider provider)
    {
        contentSignerBuilder.setProvider(provider);

        if (digestBuilder != null)
        {
            digestBuilder.setProvider(provider);
        }

        return this;
    }

    public JcaSignerInfoGeneratorBuilder setProvider(String providerName)
    {
        contentSignerBuilder.setProvider(providerName);

        if (digestBuilder != null)
        {
            digestBuilder.setProvider(providerName);
        }

        return this;
    }

    /**
     * If the passed in flag is true, the signer signature will be based on the data, not
     * a collection of signed attributes, and no signed attributes will be included.
     *
     * @return the builder object
     */
    public JcaSignerInfoGeneratorBuilder setDirectSignature(boolean hasNoSignedAttributes)
    {
        this.directSignature = hasNoSignedAttributes;

        return this;
    }

    public JcaSignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
    {
        this.signedGen = signedGen;

        return this;
    }

    public JcaSignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
    {
        this.unsignedGen = unsignedGen;

        return this;
    }

    public SignerInfoGenerator build(PrivateKey privateKey, X509Certificate origCert)
        throws OperatorCreationException, CertificateEncodingException
    {
        ContentSigner contentSigner = contentSignerBuilder.build(privateKey);

        SignerIdentifier sigId = new SignerIdentifier(new JcaX509CertificateHolder(origCert).getIssuerAndSerialNumber());

        return createGenerator(contentSigner, sigId);
    }

    public SignerInfoGenerator build(PrivateKey privateKey, byte[] keyIdentifier)
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
