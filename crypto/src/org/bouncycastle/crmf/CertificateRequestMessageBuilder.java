package org.bouncycastle.crmf;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509Name;

public class CertificateRequestMessageBuilder
{
    private final BigInteger certReqId;

    private X509ExtensionsGenerator extGenerator;
    private CertTemplateBuilder templateBuilder;
    private List controls;
    
    public CertificateRequestMessageBuilder(BigInteger certReqId)
    {
        this.certReqId = certReqId;

        this.extGenerator = new X509ExtensionsGenerator();
        this.templateBuilder = new CertTemplateBuilder();
        this.controls = new ArrayList();
    }

    public CertificateRequestMessageBuilder setSubject(X500Principal subject)
    {
        if (subject != null)
        {
            templateBuilder.setSubject(X509Name.getInstance(subject.getEncoded()));
        }

        return this;
    }

    public CertificateRequestMessageBuilder setPublicKey(SubjectPublicKeyInfo publicKey)
    {
        if (publicKey != null)
        {
            templateBuilder.setPublicKey(publicKey);
        }

        return this;
    }

    public CertificateRequestMessageBuilder setPublicKey(PublicKey publicKey)
    {
        return setPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    public CertificateRequestMessageBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean              critical,
        ASN1Encodable        value)
    {
        extGenerator.addExtension(oid, critical,  value);

        return this;
    }

    public CertificateRequestMessageBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean              critical,
        byte[]               value)
    {
        extGenerator.addExtension(oid, critical, value);

        return this;
    }

    public CertificateRequestMessageBuilder addControl(Control control)
    {
        controls.add(control);
        
        return this;
    }

    public CertificateRequestMessage build()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERInteger(certReqId));

        if (!extGenerator.isEmpty())
        {
            templateBuilder.setExtensions(extGenerator.generate());
        }

        v.add(templateBuilder.build());

        if (!controls.isEmpty())
        {
            ASN1EncodableVector controlV = new ASN1EncodableVector();

            for (Iterator it = controls.iterator(); it.hasNext();)
            {
                Control control = (Control)it.next();

                controlV.add(new AttributeTypeAndValue(control.getType(), control.getValue()));
            }

            v.add(new DERSequence(controlV));
        }

        return new CertificateRequestMessage(CertReqMsg.getInstance(new DERSequence(new DERSequence(v))));
    }
}
