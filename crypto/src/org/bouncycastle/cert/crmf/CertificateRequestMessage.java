package org.bouncycastle.cert.crmf;

import java.io.IOException;

import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
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

    public CertReqMsg toASN1Structure()
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

    public boolean verifySigningKeyPOP(ContentVerifierProvider verifierProvider)
        throws CRMFException, IllegalStateException
    {
        ProofOfPossession pop = certReqMsg.getPopo();

        if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY)
        {
            POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

            if (popoSign.getPoposkInput().getPublicKeyMAC() != null)
            {
                throw new IllegalStateException("verification requires password check");
            }

            return verifySignature(verifierProvider, popoSign);
        }
        else
        {
            throw new IllegalStateException("not Signing Key type of proof of possession");
        }
    }

    public boolean verifySigningKeyPOP(ContentVerifierProvider verifierProvider, PKMACValueVerifier macVerifier, char[] password)
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
                return verifySignature(verifierProvider, popoSign);
            }

            return false;
        }
        else
        {
            throw new IllegalStateException("not Signing Key type of proof of possession");
        }
    }

    private boolean verifySignature(ContentVerifierProvider verifierProvider, POPOSigningKey popoSign)
        throws CRMFException
    {
        ContentVerifier verifier;

        try
        {
            verifier = verifierProvider.get(popoSign.getAlgorithmIdentifier());
        }
        catch (OperatorCreationException e)
        {
            throw new CRMFException("unable to create verifier: " + e.getMessage(), e);
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