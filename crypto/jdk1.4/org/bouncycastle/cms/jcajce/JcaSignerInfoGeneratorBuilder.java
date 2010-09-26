package org.bouncycastle.cms.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class JcaSignerInfoGeneratorBuilder
    extends SignerInfoGeneratorBuilder
{
    public JcaSignerInfoGeneratorBuilder(DigestCalculatorProvider digestProvider)
    {
        super(digestProvider);
    }

    public SignerInfoGenerator build(ContentSigner contentSigner, X509Certificate certificatet)
        throws OperatorCreationException, CertificateEncodingException
    {
        return super.build(contentSigner, new JcaX509CertificateHolder(certificatet));
    }
}
