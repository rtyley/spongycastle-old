package org.bouncycastle.crypto.tls;

import java.util.Hashtable;

import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

class DefaultTlsClient implements TlsClient
{
    private CertificateVerifyer verifyer;

    // (Optional) details for client-side authentication
    private Certificate clientCert = new Certificate(new X509CertificateStructure[0]);
    private AsymmetricKeyParameter clientPrivateKey = null;
    private TlsSigner clientSigner = null;

    DefaultTlsClient(CertificateVerifyer verifyer)
    {
        this.verifyer = verifyer;
    }

    void enableClientAuthentication(Certificate clientCertificate,
        AsymmetricKeyParameter clientPrivateKey)
    {
        if (clientCertificate == null)
        {
            throw new IllegalArgumentException("'clientCertificate' cannot be null");
        }
        if (clientCertificate.certs.length == 0)
        {
            throw new IllegalArgumentException("'clientCertificate' cannot be empty");
        }
        if (clientPrivateKey == null)
        {
            throw new IllegalArgumentException("'clientPrivateKey' cannot be null");
        }
        if (!clientPrivateKey.isPrivate())
        {
            throw new IllegalArgumentException("'clientPrivateKey' must be private");
        }

        if (clientPrivateKey instanceof RSAKeyParameters)
        {
            clientSigner = new TlsRSASigner();
        }
        else if (clientPrivateKey instanceof DSAPrivateKeyParameters)
        {
            clientSigner = new TlsDSSSigner();
        }
        else
        {
            throw new IllegalArgumentException("'clientPrivateKey' type not supported: "
                + clientPrivateKey.getClass().getName());
        }

        this.clientCert = clientCertificate;
        this.clientPrivateKey = clientPrivateKey;
    }

    public CertificateVerifyer getCertificateVerifyer()
    {
        return verifyer;
    }

    public byte[] generateCertificateSignature(byte[] md5andsha1)
    {
        if (clientSigner == null)
        {
            return null;
        }

        try
        {
            return clientSigner.calculateRawSignature(clientPrivateKey, md5andsha1);
        }
        catch (CryptoException e)
        {
            // FIXME add a TlsClientContext object to allow error callbacks?
            // or else maybe declare a typed exception
//            this.failWithError(AL_fatal, AP_handshake_failure);
            throw new RuntimeException(e);
        }
    }

    public Certificate getCertificate()
    {
        return clientCert;
    }

    public Hashtable generateClientExtensions()
    {
        // TODO[SRP]
//        Hashtable clientExtensions = new Hashtable();
//        ByteArrayOutputStream srpData = new ByteArrayOutputStream();
//        TlsUtils.writeOpaque8(SRP_identity, srpData);
//
//        // TODO[SRP] RFC5054 2.8.1: ExtensionType.srp = 12
//        clientExtensions.put(Integer.valueOf(12), srpData.toByteArray());
//        return clientExtensions;
        return null;
    }

    public void processServerExtensions(Hashtable serverExtensions)
    {
        // TODO Validate/process serverExtensions (via client?)
        // TODO[SRP]
    }
}
