package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;

/**
 * Base class for EC key exchange algorithms (see RFC 4492)
 */
abstract class TlsECKeyExchange implements TlsKeyExchange
{
    protected TlsClientContext context;
    protected CertificateVerifyer verifyer;
    protected short keyExchange;
    protected TlsSigner tlsSigner;

    protected AsymmetricKeyParameter serverPublicKey;

    protected ECPublicKeyParameters ecAgreeServerPublicKey;
    protected ECPrivateKeyParameters ecAgreeClientPrivateKey = null;

    TlsECKeyExchange(TlsClientContext context, CertificateVerifyer verifyer, short keyExchange)
    {
        switch (keyExchange)
        {
            case KE_ECDHE_RSA:
                this.tlsSigner = new TlsRSASigner();
                break;
            case KE_ECDHE_ECDSA:
                this.tlsSigner = new TlsECDSASigner();
                break;
            case KE_ECDH_RSA:
            case KE_ECDH_ECDSA:
                this.tlsSigner = null;
                break;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }

        this.context = context;
        this.verifyer = verifyer;
        this.keyExchange = keyExchange;
    }

    public void skipServerCertificate() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        X509CertificateStructure x509Cert = serverCertificate.certs[0];
        SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();

        try
        {
            this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
        }

        // Sanity check the PublicKeyFactory
        if (this.serverPublicKey.isPrivate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // TODO 
        /*
         * Perform various checks per RFC2246 7.4.2: "Unless otherwise specified, the
         * signing algorithm for the certificate must be the same as the algorithm for the
         * certificate key."
         */

        // TODO Should the 'instanceof' tests be replaces with stricter checks on keyInfo.getAlgorithmId()?

        switch (this.keyExchange)
        {
            case KE_ECDH_ECDSA:
                if (!(this.serverPublicKey instanceof ECPublicKeyParameters))
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.keyAgreement);
                // TODO The algorithm used to sign the certificate should be ECDSA.
//                x509Cert.getSignatureAlgorithm();
                this.ecAgreeServerPublicKey = validateECPublicKey((ECPublicKeyParameters)this.serverPublicKey);
                break;
            case KE_ECDHE_ECDSA:
                if (!(this.serverPublicKey instanceof ECPublicKeyParameters))
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                // TODO Validate ECDSA public key
                break;
            case KE_ECDH_RSA:
                if (!(this.serverPublicKey instanceof ECPublicKeyParameters))
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.keyAgreement);
                // TODO The algorithm used to sign the certificate should be RSA.
//              x509Cert.getSignatureAlgorithm();
                this.ecAgreeServerPublicKey = validateECPublicKey((ECPublicKeyParameters)this.serverPublicKey);
                break;
            case KE_ECDHE_RSA:
                if (!(this.serverPublicKey instanceof RSAKeyParameters))
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                // TODO Validate RSA public key
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
        }

        /*
         * Verify them.
         */
        if (!this.verifyer.isValid(serverCertificate.getCerts()))
        {
            throw new TlsFatalAlert(AlertDescription.user_canceled);
        }
    }

    protected boolean areOnSameCurve(ECDomainParameters a, ECDomainParameters b)
    {
        // TODO Move to ECDomainParameters.equals() or other utility method?
        return a.getCurve().equals(b.getCurve())
            && a.getG().equals(b.getG())
            && a.getN().equals(b.getN())
            && a.getH().equals(b.getH());
    }
    
    protected byte[] externalizeKey(ECPublicKeyParameters keyParameters) throws IOException
    {
        // TODO Add support for compressed encoding and SPF extension

        /*
         * RFC 4492 5.7. ...an elliptic curve point in uncompressed or compressed format.
         * Here, the format MUST conform to what the server has requested through a
         * Supported Point Formats Extension if this extension was used, and MUST be
         * uncompressed if this extension was not used.
         */
        return keyParameters.getQ().getEncoded();
    }

    protected AsymmetricCipherKeyPair generateECKeyPair(ECDomainParameters ecParams)
    {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(
            ecParams, context.getSecureRandom());
        keyPairGenerator.init(keyGenerationParameters);
        return keyPairGenerator.generateKeyPair();
    }

    protected void generateEphemeralClientKeyExchange(ECDomainParameters ecParams, OutputStream os) throws IOException
    {
        AsymmetricCipherKeyPair ecAgreeClientKeyPair = generateECKeyPair(ecParams);
        this.ecAgreeClientPrivateKey = (ECPrivateKeyParameters)ecAgreeClientKeyPair.getPrivate();

        byte[] keData = externalizeKey((ECPublicKeyParameters)ecAgreeClientKeyPair.getPublic());
        TlsUtils.writeUint24(keData.length + 1, os);
        TlsUtils.writeOpaque8(keData, os);
    }

    protected byte[] calculateECDHBasicAgreement(ECPublicKeyParameters publicKey,
        ECPrivateKeyParameters privateKey)
    {
        ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreement = basicAgreement.calculateAgreement(publicKey);
        return BigIntegers.asUnsignedByteArray(agreement);
    }

    protected void validateKeyUsage(X509CertificateStructure c, int keyUsageBits) throws IOException
    {
        X509Extensions exts = c.getTBSCertificate().getExtensions();
        if (exts != null)
        {
            X509Extension ext = exts.getExtension(X509Extension.keyUsage);
            if (ext != null)
            {
                DERBitString ku = KeyUsage.getInstance(ext);
                int bits = ku.getBytes()[0] & 0xff;
                if ((bits & keyUsageBits) != keyUsageBits)
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }
            }
        }
    }

    protected ECPublicKeyParameters validateECPublicKey(ECPublicKeyParameters key) throws IOException
    {
        // TODO Check RFC 4492 for validation
        return key;
    }
}
