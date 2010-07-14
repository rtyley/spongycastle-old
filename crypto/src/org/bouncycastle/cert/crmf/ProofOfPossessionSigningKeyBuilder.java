package org.bouncycastle.cert.crmf;

import java.io.IOException;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.POPOSigningKeyInput;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;

public class ProofOfPossessionSigningKeyBuilder
{
    private SubjectPublicKeyInfo pubKeyInfo;
    private GeneralName name;
    private PKMACValue publicKeyMAC;

    public ProofOfPossessionSigningKeyBuilder(SubjectPublicKeyInfo pubKeyInfo)
    {
        this.pubKeyInfo = pubKeyInfo;
    }

    public ProofOfPossessionSigningKeyBuilder setSender(GeneralName name)
    {
        this.name = name;

        return this;
    }

    public ProofOfPossessionSigningKeyBuilder setMacBuilder(PKMACValue publicKeyMAC)
    {
        this.publicKeyMAC = publicKeyMAC;

        return this;
    }

    public POPOSigningKey build(ContentSigner signer)
    {
        if (name != null || publicKeyMAC != null)
        {
            throw new IllegalStateException("name and publicKeyMAC cannot both be set.");
        }

        DEROutputStream dOut = new DEROutputStream(signer.getSigningOutputStream());

        POPOSigningKeyInput popo;

        if (name != null)
        {
            popo = new POPOSigningKeyInput(name, pubKeyInfo);
        }
        else
        {
            popo = new POPOSigningKeyInput(publicKeyMAC, pubKeyInfo);
        }

        try
        {
            dOut.writeObject(popo);

            dOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFRuntimeException("unable to encode proof of possession: " + e.getMessage(), e);
        }

        return new POPOSigningKey(popo, signer.getAlgorithmIdentifier(), new DERBitString(signer.getSignature()));
    }
}
