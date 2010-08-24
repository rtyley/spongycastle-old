package org.bouncycastle.cert.crmf;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.POPOPrivKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.operator.ContentSigner;

public class CertificateRequestMessageBuilder
{
    private final BigInteger certReqId;

    private X509ExtensionsGenerator extGenerator;
    private CertTemplateBuilder templateBuilder;
    private List controls;
    private ContentSigner popSigner;
    private PKMACValueGenerator pkmacGenerator;
    private char[] password;
    private GeneralName sender;
    private POPOPrivKey popoPrivKey;

    public CertificateRequestMessageBuilder(BigInteger certReqId)
    {
        this.certReqId = certReqId;

        this.extGenerator = new X509ExtensionsGenerator();
        this.templateBuilder = new CertTemplateBuilder();
        this.controls = new ArrayList();
    }

    public CertificateRequestMessageBuilder setPublicKey(SubjectPublicKeyInfo publicKey)
    {
        if (publicKey != null)
        {
            templateBuilder.setPublicKey(publicKey);
        }

        return this;
    }

    public CertificateRequestMessageBuilder setIssuer(X509Name issuer)
    {
        if (issuer != null)
        {
            templateBuilder.setIssuer(issuer);
        }

        return this;
    }

    public CertificateRequestMessageBuilder setSubject(X509Name subject)
    {
        if (subject != null)
        {
            templateBuilder.setSubject(subject);
        }

        return this;
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

    public CertificateRequestMessageBuilder setProofOfPossessionSigningKeySigner(ContentSigner popSigner)
    {
        this.popSigner = popSigner;

        return this;
    }

    public CertificateRequestMessageBuilder setProofOfPossessionSubsequentMessage(SubsequentMessage msg)
    {
        this.popoPrivKey = new POPOPrivKey(msg);

        return this;
    }

    public CertificateRequestMessageBuilder setAuthInfoPKMAC(PKMACValueGenerator pkmacGenerator, char[] password)
    {
        this.pkmacGenerator = pkmacGenerator;
        this.password = password;

        return this;
    }

    public CertificateRequestMessageBuilder setAuthInfoSender(GeneralName sender)
    {
        this.sender = sender;

        return this;
    }

    public CertificateRequestMessage build()
        throws CRMFException
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

        CertRequest request = CertRequest.getInstance(new DERSequence(v));

        v = new ASN1EncodableVector();

        v.add(request);

        if (popSigner != null)
        {
            SubjectPublicKeyInfo pubKeyInfo = request.getCertTemplate().getPublicKey();
            ProofOfPossessionSigningKeyBuilder builder = new ProofOfPossessionSigningKeyBuilder(pubKeyInfo);

            if (sender != null)
            {
                builder.setSender(sender);
            }
            else
            {
                builder.setPublicKeyMac(pkmacGenerator, password);
            }

            v.add(new ProofOfPossession(builder.build(popSigner)));
        }
        if (popoPrivKey != null)
        {
            v.add(new ProofOfPossession(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, popoPrivKey));
        }

        return new CertificateRequestMessage(CertReqMsg.getInstance(new DERSequence(v)));
    }
}