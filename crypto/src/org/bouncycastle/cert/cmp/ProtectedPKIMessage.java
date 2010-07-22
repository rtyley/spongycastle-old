package org.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;

public class ProtectedPKIMessage
{
    private PKIMessage pkiMessage;

    public ProtectedPKIMessage(PKIMessage pkiMessage)
    {
        this.pkiMessage = pkiMessage;
    }

    public PKIHeader getHeader()
    {
        return pkiMessage.getHeader();
    }

    public PKIBody getBody()
    {
        return pkiMessage.getBody();
    }

    public PKIMessage toPKIMessage()
    {
        return pkiMessage;
    }

    public X509CertificateHolder[] getCertificates()
    {
        CMPCertificate[] certs = pkiMessage.getExtraCerts();

        if (certs == null)
        {
            return new X509CertificateHolder[0];
        }

        X509CertificateHolder[] res = new X509CertificateHolder[certs.length];
        for (int i = 0; i != certs.length; i++)
        {
            res[i] = new X509CertificateHolder(certs[i].getX509v3PKCert());
        }

        return res;
    }

    public boolean verify(ContentVerifier verifier)
        throws CMPException
    {
        try
        {
            verifier.setup(pkiMessage.getHeader().getProtectionAlg());

            return verifySignature(pkiMessage.getProtection().getBytes(), verifier);
        }
        catch (Exception e)
        {
            throw new CMPException("unable to verify signature: " + e.getMessage(), e);
        }
    }

    private boolean verifySignature(byte[] signature, ContentVerifier verifier)
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(pkiMessage.getHeader());
        v.add(pkiMessage.getBody());

        OutputStream sOut = verifier.getOutputStream();

        sOut.write(new DERSequence(v).getDEREncoded());

        sOut.close();

        return verifier.verify(signature);
    }
}
