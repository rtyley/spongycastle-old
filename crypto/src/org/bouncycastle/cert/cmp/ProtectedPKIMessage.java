package org.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.util.Arrays;

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

    public boolean verify(ContentVerifierProvider verifierProvider)
        throws CMPException
    {
        ContentVerifier verifier;
        try
        {
            verifier = verifierProvider.get(pkiMessage.getHeader().getProtectionAlg());

            return verifySignature(pkiMessage.getProtection().getBytes(), verifier);
        }
        catch (Exception e)
        {
            throw new CMPException("unable to verify signature: " + e.getMessage(), e);
        }
    }

    public boolean verify(PKMACBuilder pkMacBuilder, char[] password)
        throws CMPException
    {
        if (!CMPObjectIdentifiers.passwordBasedMac.equals(pkiMessage.getHeader().getProtectionAlg().getAlgorithm()))
        {
            throw new CMPException("protection algorithm not mac based");
        }


        try
        {
            pkMacBuilder.setParameters(PBMParameter.getInstance(pkiMessage.getHeader().getProtectionAlg().getParameters()));
            MacCalculator calculator = pkMacBuilder.build(password);

            OutputStream macOut = calculator.getOutputStream();

            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(pkiMessage.getHeader());
            v.add(pkiMessage.getBody());

            macOut.write(new DERSequence(v).getDEREncoded());

            macOut.close();

            return Arrays.areEqual(calculator.getMac(), pkiMessage.getProtection().getBytes());
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
