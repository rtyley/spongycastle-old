package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * ECDH key exchange (see RFC 4492)
 */
class TlsECDHKeyExchange extends TlsECKeyExchange
{
    TlsECDHKeyExchange(TlsClientContext context, CertificateVerifyer verifyer, int keyExchange)
    {
        super(context, verifyer, keyExchange);
    }

    public void skipServerCertificate() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void skipServerKeyExchange() throws IOException
    {
        // do nothing
    }

    public void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException
    {
        if (ecAgreeClientPrivateKey != null)
        {
            TlsUtils.writeUint24(0, os);
        }
        else
        {
            generateEphemeralClientKeyExchange(ecAgreeServerPublicKey.getParameters(), os);
        }
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        return calculateECDHBasicAgreement(ecAgreeServerPublicKey, ecAgreeClientPrivateKey);
    }

    // TODO
//    public void processServerCertificateRequest(short[] certificateTypes,
//        Vector certificateAuthorities)
//    {
//        boolean fixedAuthenticationOfferedByServer = ecdsaFixedOfferedByServer(certificateTypes);
//        if (fixedAuthenticationOfferedByServer && clientPrivateKey != null
//            && serverPublicKey != null && serverPublicKey instanceof ECPublicKeyParameters
//            && clientPrivateKey instanceof ECPrivateKeyParameters)
//        {
//            ECPublicKeyParameters ecServerPublicKey = (ECPublicKeyParameters)serverPublicKey;
//            ECPrivateKeyParameters ecClientPrivateKey = (ECPrivateKeyParameters)clientPrivateKey;
//
//            if (areOnSameCurve(ecServerPublicKey.getParameters(), ecClientPrivateKey.getParameters()))
//            {
//                ecAgreeClientPrivateKey = ecClientPrivateKey;
//            }
//
//            // TODO RSA_fixed_ECDH
//        }
//    }
//
//    public boolean sendCertificateVerify()
//    {
//        // TODO Check we are even using client auth
//        return !usingFixedAuthentication;
//    }
//
//    protected boolean ecdsaFixedOfferedByServer(short[] certificateTypes)
//    {
//        boolean fixedAuthenticationOfferedByServer = false;
//        for (int i = 0; i < certificateTypes.length; i++)
//        {
//            if (certificateTypes[i] == ClientCertificateType.ecdsa_fixed_ecdh)
//            {
//                fixedAuthenticationOfferedByServer = true;
//                break;
//            }
//        }
//        return fixedAuthenticationOfferedByServer;
//    }
}
