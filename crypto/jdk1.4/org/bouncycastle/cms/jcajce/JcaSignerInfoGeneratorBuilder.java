package org.spongycastle.cms.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.spongycastle.cert.jcajce.JcaX509CertificateHolder;
import org.spongycastle.cms.CMSAttributeTableGenerator;
import org.spongycastle.cms.SignerInfoGenerator;
import org.spongycastle.cms.SignerInfoGeneratorBuilder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DigestCalculatorProvider;
import org.spongycastle.operator.OperatorCreationException;

public class JcaSignerInfoGeneratorBuilder
    extends SignerInfoGeneratorBuilder
{
    public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider)
    {
        super(digestProvider);
    }

    /**
     * If the passed in flag is true, the signer signature will be based on the data, not
     * a collection of signed attributes, and no signed attributes will be included.
     *
     * @return the builder object
     */
    public SignerInfoGeneratorBuilder setDirectSignature(boolean hasNoSignedAttributes)
    {
        super.setDirectSignature(hasNoSignedAttributes);

        return this;
    }

    public SignerInfoGeneratorBuilder setSignedAttributeGenerator(CMSAttributeTableGenerator signedGen)
    {
        super.setSignedAttributeGenerator(signedGen);

        return this;
    }

    public SignerInfoGeneratorBuilder setUnsignedAttributeGenerator(CMSAttributeTableGenerator unsignedGen)
    {
        super.setUnsignedAttributeGenerator(unsignedGen);

        return this;
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, X509Certificate certificate)
        throws OperatorCreationException, CertificateEncodingException
    {
        return super.build(contentSigner, new JcaX509CertificateHolder(certificate));
    }
}
