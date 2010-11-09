package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.io.SignerInputStream;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * ECDHE key exchange (see RFC 4492)
 */
class TlsECDHEKeyExchange extends TlsECKeyExchange
{
    TlsECDHEKeyExchange(TlsProtocolHandler handler, CertificateVerifyer verifyer,
        short keyExchange,
        // TODO Replace with an interface e.g. TlsClientAuth
        Certificate clientCert, AsymmetricKeyParameter clientPrivateKey)
    {
        super(handler, verifyer, keyExchange, clientCert, clientPrivateKey);
    }

    public void skipServerCertificate() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void skipServerKeyExchange() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException
    {
        Signer signer = initSigner(tlsSigner, securityParameters);
        InputStream sigIn = new SignerInputStream(is, signer);

        short curveType = TlsUtils.readUint8(sigIn);
        ECDomainParameters curve_params;

        //  Currently, we only support named curves
        if (curveType == ECCurveType.named_curve)
        {
            int namedCurve = TlsUtils.readUint16(sigIn);

            // TODO Check namedCurve is one we offered?

            curve_params = NamedCurve.getECParameters(namedCurve);
        }
        else
        {
            // TODO Add support for explicit curve parameters (read from sigIn)

            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        byte[] publicBytes = TlsUtils.readOpaque8(sigIn);

        byte[] sigByte = TlsUtils.readOpaque16(is);
        if (!signer.verifySignature(sigByte))
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        // TODO Check curve_params not null

        ECPoint Q = curve_params.getCurve().decodePoint(publicBytes);

        serverEphemeralPublicKey = new ECPublicKeyParameters(Q, curve_params);
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException
    {
        generateEphemeralClientKeyExchange(serverEphemeralPublicKey, os);
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        return calculateECDHBasicAgreement(serverEphemeralPublicKey,
            clientEphemeralKeyPair.getPrivate());
    }

    protected Signer initSigner(TlsSigner tlsSigner, SecurityParameters securityParameters)
    {
        Signer signer = tlsSigner.createVerifyer(this.serverPublicKey);
        signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return signer;
    }

//    public void processServerCertificateRequest(byte[] certificateTypes,
//        Vector certificateAuthorities)
//    {
//    }
//
//    public boolean sendCertificateVerify()
//    {
//        return true;
//    }
}
