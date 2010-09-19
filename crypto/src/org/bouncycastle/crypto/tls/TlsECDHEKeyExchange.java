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
        handler.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
    }

    public void skipServerKeyExchange() throws IOException
    {
        handler.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
    }

    public void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException
    {
        if (tlsSigner == null)
        {
            handler.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
        }

        InputStream sigIn = is;
        Signer signer = null;

        if (tlsSigner != null)
        {
            signer = initSigner(tlsSigner, securityParameters);
            sigIn = new SignerInputStream(is, signer);
        }

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

            handler.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
            return;
        }

        byte[] publicBytes = TlsUtils.readOpaque8(sigIn);

        if (signer != null)
        {
            byte[] sigByte = TlsUtils.readOpaque16(is);

            if (!signer.verifySignature(sigByte))
            {
                handler.failWithError(AlertLevel.fatal, AlertDescription.bad_certificate);
            }
        }

        // TODO Check curve_params not null

        ECPoint Q = curve_params.getCurve().decodePoint(publicBytes);

        serverEphemeralPublicKey = new ECPublicKeyParameters(Q, curve_params);
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException
    {
        clientEphemeralKeyPair = generateECKeyPair(serverEphemeralPublicKey.getParameters());
        byte[] keData = externalizeKey((ECPublicKeyParameters)clientEphemeralKeyPair.getPublic());
        TlsUtils.writeUint24(keData.length + 1, os);
        TlsUtils.writeOpaque8(keData, os);
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        return calculateECDHEPreMasterSecret((ECPublicKeyParameters)serverEphemeralPublicKey,
            clientEphemeralKeyPair.getPrivate());
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
