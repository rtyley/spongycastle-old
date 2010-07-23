package org.bouncycastle.cert.crmf;

import java.io.IOException;

import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;

public class CertificateRequestMessage
{
    private final CertReqMsg certReqMsg;

    public CertificateRequestMessage(byte[] certReqMsg)
    {
        this(CertReqMsg.getInstance(certReqMsg));
    }

    protected CertificateRequestMessage(CertReqMsg certReqMsg)
    {
        this.certReqMsg = certReqMsg;
    }

    public CertReqMsg getCertReqMsg()
    {
        return certReqMsg;
    }

    public CertTemplate getCertTemplate()
    {
        return this.certReqMsg.getCertReq().getCertTemplate();
    }

    public boolean hasProofOfPossession()
    {
        return this.certReqMsg.getPopo() != null;
    }

    public int getProofOfPossessionType()
    {
        return this.certReqMsg.getPopo().getType();
    }

    public boolean hasSigningKeyProofOfPossessionWithPKMAC()
    {
        ProofOfPossession pop = certReqMsg.getPopo();

        if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY)
        {
            POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

            return popoSign.getPoposkInput().getPublicKeyMAC() != null;
        }

        return false;
    }

    public boolean verifySigningKeyPOP(ContentVerifier verifier)
        throws IllegalStateException
    {
        ProofOfPossession pop = certReqMsg.getPopo();

        if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY)
        {
            POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

            if (popoSign.getPoposkInput().getPublicKeyMAC() != null)
            {
                throw new IllegalStateException("verification requires password check");
            }

            return verifySignature(verifier, popoSign);
        }
        else
        {
            throw new IllegalStateException("not Signing Key type of proof of possession");
        }
    }

    public boolean verifySigningKeyPOP(ContentVerifier verifier, PKMACValueVerifier macVerifier, char[] password)
        throws CRMFException, IllegalStateException
    {
        ProofOfPossession pop = certReqMsg.getPopo();

        if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY)
        {
            POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

            if (popoSign.getPoposkInput().getSender() != null)
            {
                throw new IllegalStateException("no PKMAC present in proof of possession");
            }

            PKMACValue pkMAC = popoSign.getPoposkInput().getPublicKeyMAC();

            if (macVerifier.verify(pkMAC, password, this.getCertTemplate().getPublicKey()))
            {
                return verifySignature(verifier, popoSign);
            }

            return false;
        }
        else
        {
            throw new IllegalStateException("not Signing Key type of proof of possession");
        }
    }

    private boolean verifySignature(ContentVerifier verifier, POPOSigningKey popoSign)
    {
        try
        {
            verifier.setup(popoSign.getAlgorithmIdentifier());
        }
        catch (OperatorCreationException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

        CRMFUtil.derEncodeToStream(popoSign.getPoposkInput(), verifier.getOutputStream());

        return verifier.verify(popoSign.getSignature().getBytes());
    }

    public byte[] getEncoded()
        throws IOException
    {
        return certReqMsg.getEncoded();
    }
}