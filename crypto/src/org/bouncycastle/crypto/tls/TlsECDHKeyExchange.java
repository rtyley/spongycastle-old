package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * ECDH key exchange (see RFC 4492)
 */
class TlsECDHKeyExchange extends TlsECKeyExchange
{
    boolean usingFixedAuthentication;

    TlsECDHKeyExchange(TlsProtocolHandler handler, CertificateVerifyer verifyer, short keyExchange,
        // TODO Replace with an interface e.g. TlsClientAuth
        Certificate clientCert, AsymmetricKeyParameter clientPrivateKey)
    {
        super(handler, verifyer, keyExchange, clientCert, clientPrivateKey);
    }

    public void skipServerCertificate() throws IOException
    {
        handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unexpected_message);
    }

    public void skipServerKeyExchange() throws IOException
    {
        // do nothing
    }

    public void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException
    {
        handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unexpected_message);
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException
    {
        if (usingFixedAuthentication)
        {
            TlsUtils.writeUint24(0, os);
        }
        else
        {
            clientEphemeralKeyPair = generateECKeyPair(((ECKeyParameters)serverPublicKey).getParameters());
            byte[] keData = externalizeKey((ECPublicKeyParameters)clientEphemeralKeyPair.getPublic());
            TlsUtils.writeUint24(keData.length + 1, os);
            TlsUtils.writeOpaque8(keData, os);
        }
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        CipherParameters privateKey = null;
        if (usingFixedAuthentication)
        {
            privateKey = this.clientPrivateKey;
        }
        else
        {
            privateKey = clientEphemeralKeyPair.getPrivate();
        }
        return calculateECDHEPreMasterSecret((ECPublicKeyParameters)serverPublicKey, privateKey);
    }

    // TODO
//    public void processServerCertificateRequest(byte[] certificateTypes,
//        Vector certificateAuthorities)
//    {
//        usingFixedAuthentication = false;
//        boolean fixedAuthenticationOfferedByServer = ecdsaFixedOfferedByServer(certificateTypes);
//        if (fixedAuthenticationOfferedByServer && clientPrivateKey != null
//            && serverPublicKey != null && serverPublicKey instanceof ECPublicKeyParameters
//            && clientPrivateKey instanceof ECKeyParameters)
//        {
//            ECPublicKeyParameters ecPublicKeyParameters = (ECPublicKeyParameters)serverPublicKey;
//            ECKeyParameters ecClientPrivateKey = (ECKeyParameters)clientPrivateKey;
//
//            if (ecPublicKeyParameters.getParameters().getCurve().equals(
//                ecClientPrivateKey.getParameters().getCurve()))
//            {
//                usingFixedAuthentication = true;
//            }
//            // todo RSA_fixed_ECDE
//        }
//    }
//
//    public boolean sendCertificateVerify()
//    {
//        return !usingFixedAuthentication;
//    }
//
//    private boolean ecdsaFixedOfferedByServer(byte[] certificateTypes)
//    {
//        boolean fixedAuthenticationOfferedByServer = false;
//        for (int i = 0; i < certificateTypes.length; i++)
//        {
//            if (certificateTypes[i] == ClientCertificateTypes.ECDSA_FIXED_ECDH)
//            {
//                fixedAuthenticationOfferedByServer = true;
//                break;
//            }
//        }
//        return fixedAuthenticationOfferedByServer;
//    }
}
