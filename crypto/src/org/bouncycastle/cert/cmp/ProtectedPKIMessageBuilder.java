package org.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;

public class ProtectedPKIMessageBuilder
{
    private PKIHeaderBuilder hdrBuilder;
    private PKIBody body;
    private List extraCerts = new ArrayList();

    /**
     * Commence a message with the header type CMP_2000
     *
     * @param sender message sender
     * @param recipient intended recipient
     */
    public ProtectedPKIMessageBuilder(GeneralName sender, GeneralName recipient)
    {
        this(PKIHeader.CMP_2000, sender, recipient);
    }

    public ProtectedPKIMessageBuilder(int pvno, GeneralName sender, GeneralName recipient)
    {
        hdrBuilder = new PKIHeaderBuilder(pvno, sender, recipient);
    }

    public ProtectedPKIMessageBuilder setTransactionID(byte[] tid)
    {
        hdrBuilder.setTransactionID(tid);

        return this;
    }

    public ProtectedPKIMessageBuilder setFreeText(PKIFreeText freeText)
    {
        hdrBuilder.setFreeText(freeText);

        return this;
    }

    public ProtectedPKIMessageBuilder setGeneralInfo(InfoTypeAndValue[] genInfo)
    {
        hdrBuilder.setGeneralInfo(genInfo);

        return this;
    }

    public ProtectedPKIMessageBuilder setMessageTime(Date time)
    {
        hdrBuilder.setMessageTime(new DERGeneralizedTime(time));

        return this;
    }

    public ProtectedPKIMessageBuilder setRecipKID(byte[] kid)
    {
        hdrBuilder.setRecipKID(kid);

        return this;
    }

    public ProtectedPKIMessageBuilder setRecipNonce(byte[] nonce)
    {
        hdrBuilder.setRecipNonce(nonce);

        return this;
    }

    public ProtectedPKIMessageBuilder setSenderKID(byte[] kid)
    {
        hdrBuilder.setSenderKID(kid);

        return this;
    }

    public ProtectedPKIMessageBuilder setSenderNonce(byte[] nonce)
    {
        hdrBuilder.setSenderNonce(nonce);

        return this;
    }

    /**
     * set the body for the message
     *
     */
    public ProtectedPKIMessageBuilder setBody(PKIBody body)
    {
        this.body = body;

        return this;
    }

    public ProtectedPKIMessageBuilder addCMPCertificate(X509CertificateHolder extraCert)
    {
        extraCerts.add(extraCert);

        return this;
    }

    public ProtectedPKIMessage build(ContentSigner signer)
        throws CMPException
    {
        hdrBuilder.setProtectionAlg(signer.getAlgorithmIdentifier());

        PKIHeader header = hdrBuilder.build();
        
        try
        {
            DERBitString protection = new DERBitString(calculateSignature(signer, header, body));

            if (!extraCerts.isEmpty())
            {
                CMPCertificate[] cmpCerts = new CMPCertificate[extraCerts.size()];

                for (int i = 0; i != cmpCerts.length; i++)
                {
                    cmpCerts[i] = new CMPCertificate(((X509CertificateHolder)extraCerts.get(i)).toASN1Structure());
                }

                return new ProtectedPKIMessage(new PKIMessage(header, body, protection, cmpCerts));
            }
            else
            {
                return new ProtectedPKIMessage(new PKIMessage(header, body, protection));
            }
        }
        catch (IOException e)
        {
            throw new CMPException("unable to encode signature input: " + e.getMessage(), e);
        }
    }

    private byte[] calculateSignature(ContentSigner signer, PKIHeader header, PKIBody body)
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(header);
        v.add(body);

        OutputStream sOut = signer.getOutputStream();

        sOut.write(new DERSequence(v).getDEREncoded());

        sOut.close();

        return signer.getSignature();
    }
}
