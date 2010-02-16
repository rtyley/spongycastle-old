package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.io.SignerInputStream;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;

/**
 * A generic TLS 1.0 key exchange.
 */
class DefaultTlsKeyExchange extends TlsKeyExchange
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private TlsProtocolHandler handler;
    private CertificateVerifyer verifyer;
    private short keyExchange;
    private TlsSigner tlsSigner;

    private AsymmetricKeyParameter serverPublicKey = null;

    private RSAKeyParameters rsaServerPublicKey = null;

    private DHPublicKeyParameters dhAgreeServerPublicKey = null;
    private AsymmetricCipherKeyPair dhAgreeClientKeyPair = null;

    private byte[] pms;

    DefaultTlsKeyExchange(TlsProtocolHandler handler, CertificateVerifyer verifyer,
        short keyExchange)
    {
        switch (keyExchange)
        {
            case TlsKeyExchange.KE_RSA:
            case TlsKeyExchange.KE_DH_RSA:
            case TlsKeyExchange.KE_DH_DSS:
                this.tlsSigner = null;
                break;
            case TlsKeyExchange.KE_DHE_RSA:
                this.tlsSigner = new TlsRSASigner();
                break;
            case TlsKeyExchange.KE_DHE_DSS:
                this.tlsSigner = new TlsDSSSigner();
                break;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }

        this.handler = handler;
        this.verifyer = verifyer;
        this.keyExchange = keyExchange;
    }

    protected void skipServerCertificate() throws IOException
    {
        handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unexpected_message);
    }

    protected void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        X509CertificateStructure x509Cert = serverCertificate.certs[0];
        SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();

        try
        {
            this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
        }
        catch (RuntimeException e)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_unsupported_certificate);
        }

        // Sanity check the PublicKeyFactory
        if (this.serverPublicKey.isPrivate())
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_internal_error);
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
            case TlsKeyExchange.KE_RSA:
                if (!(this.serverPublicKey instanceof RSAKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal,
                        TlsProtocolHandler.AP_certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);
                this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters)this.serverPublicKey);
                break;
            case TlsKeyExchange.KE_DH_DSS:
                if (!(this.serverPublicKey instanceof DHPublicKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal,
                        TlsProtocolHandler.AP_certificate_unknown);
                }
                // TODO The algorithm used to sign the certificate should be DSS.
//                x509Cert.getSignatureAlgorithm();
                this.dhAgreeServerPublicKey = validateDHPublicKey((DHPublicKeyParameters)this.serverPublicKey);
                break;
            case TlsKeyExchange.KE_DH_RSA:
                if (!(this.serverPublicKey instanceof DHPublicKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal,
                        TlsProtocolHandler.AP_certificate_unknown);
                }
                // TODO The algorithm used to sign the certificate should be RSA.
//              x509Cert.getSignatureAlgorithm();
                this.dhAgreeServerPublicKey = validateDHPublicKey((DHPublicKeyParameters)this.serverPublicKey);
                break;
            case TlsKeyExchange.KE_DHE_RSA:
                if (!(this.serverPublicKey instanceof RSAKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal,
                        TlsProtocolHandler.AP_certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                break;
            case TlsKeyExchange.KE_DHE_DSS:
                if (!(this.serverPublicKey instanceof DSAPublicKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal,
                        TlsProtocolHandler.AP_certificate_unknown);
                }
                break;
            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal,
                    TlsProtocolHandler.AP_unsupported_certificate);
        }

        /*
         * Verify them.
         */
        if (!this.verifyer.isValid(serverCertificate.getCerts()))
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_user_canceled);
        }
    }

    protected void skipServerKeyExchange() throws IOException
    {
        // RFC 2246 7.4.3.
        switch (this.keyExchange)
        {
            case KE_RSA:
            case KE_DH_DSS:
            case KE_DH_RSA:
                break;

            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal,
                    TlsProtocolHandler.AP_unexpected_message);
        }
    }

    protected void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException
    {
        switch (this.keyExchange)
        {
            case TlsKeyExchange.KE_DHE_RSA:
            case TlsKeyExchange.KE_DHE_DSS:
                processDHServerKeyExchange(is, initSigner(tlsSigner, securityParameters));
                break;

            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal,
                    TlsProtocolHandler.AP_unexpected_message);
        }
    }

    protected byte[] generateClientKeyExchange() throws IOException
    {
        switch (this.keyExchange)
        {
            case TlsKeyExchange.KE_RSA:
            {
                /*
                 * We are doing RSA key exchange. We will choose a pre master secret and
                 * send it rsa encrypted to the server.
                 * 
                 * Prepare pre master secret.
                 */
                pms = new byte[48];
                handler.getRandom().nextBytes(pms);
                TlsUtils.writeVersion(pms, 0);

                /*
                 * Encode the pms and send it to the server.
                 * 
                 * Prepare an PKCS1Encoding with good random padding.
                 */
                PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
                encoding.init(true, new ParametersWithRandom(this.rsaServerPublicKey,
                    handler.getRandom()));

                try
                {
                    return encoding.processBlock(pms, 0, pms.length);
                }
                catch (InvalidCipherTextException e)
                {
                    /*
                     * This should never happen, only during decryption.
                     */
                    handler.failWithError(TlsProtocolHandler.AL_fatal,
                        TlsProtocolHandler.AP_internal_error);
                    return null; // Unreachable!
                }
            }

            case TlsKeyExchange.KE_DH_DSS:
            case TlsKeyExchange.KE_DH_RSA:
            case TlsKeyExchange.KE_DHE_DSS:
            case TlsKeyExchange.KE_DHE_RSA:
            {
                // TODO RFC 2246 7.4.72
                /*
                 * If the client certificate already contains a suitable Diffie-Hellman
                 * key, then Yc is implicit and does not need to be sent again. In this
                 * case, the Client Key Exchange message will be sent, but will be empty.
                 */
//                return new byte[0];

                /*
                 * Generate a keypair (using parameters from server key) and send the
                 * public value to the server.
                 */
                DHBasicKeyPairGenerator dhGen = new DHBasicKeyPairGenerator();
                dhGen.init(new DHKeyGenerationParameters(handler.getRandom(),
                    dhAgreeServerPublicKey.getParameters()));
                this.dhAgreeClientKeyPair = dhGen.generateKeyPair();
                BigInteger Yc = ((DHPublicKeyParameters)dhAgreeClientKeyPair.getPublic()).getY();
                return BigIntegers.asUnsignedByteArray(Yc);
            }

            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal,
                    TlsProtocolHandler.AP_unexpected_message);
                return null; // Unreachable!
        }
    }

    protected byte[] generatePremasterSecret() throws IOException
    {
        switch (this.keyExchange)
        {
            case TlsKeyExchange.KE_RSA:
                byte[] tmp = this.pms;
                this.pms = null;
                return tmp;

            case TlsKeyExchange.KE_DHE_DSS:
            case TlsKeyExchange.KE_DHE_RSA:
            {
                /*
                 * Diffie-Hellman basic key agreement
                 */
                DHBasicAgreement dhAgree = new DHBasicAgreement();
                dhAgree.init(dhAgreeClientKeyPair.getPrivate());
                BigInteger agreement = dhAgree.calculateAgreement(dhAgreeServerPublicKey);
                return BigIntegers.asUnsignedByteArray(agreement);
            }

            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal,
                    TlsProtocolHandler.AP_unexpected_message);
                return null; // Unreachable!
        }
    }

    private void validateKeyUsage(X509CertificateStructure c, int keyUsageBits) throws IOException
    {
        X509Extensions exts = c.getTBSCertificate().getExtensions();
        if (exts != null)
        {
            X509Extension ext = exts.getExtension(X509Extensions.KeyUsage);
            if (ext != null)
            {
                DERBitString ku = KeyUsage.getInstance(ext);
                int bits = ku.getBytes()[0] & 0xff;
                if ((bits & keyUsageBits) != keyUsageBits)
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal,
                        TlsProtocolHandler.AP_certificate_unknown);
                }
            }
        }
    }

    private Signer initSigner(TlsSigner tlsSigner, SecurityParameters securityParameters)
    {
        Signer signer = tlsSigner.createVerifyer(this.serverPublicKey);
        signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return signer;
    }

    private void processDHServerKeyExchange(InputStream is, Signer signer) throws IOException
    {
        InputStream sigIn = is;
        if (signer != null)
        {
            sigIn = new SignerInputStream(is, signer);
        }

        byte[] pBytes = TlsUtils.readOpaque16(sigIn);
        byte[] gBytes = TlsUtils.readOpaque16(sigIn);
        byte[] YsBytes = TlsUtils.readOpaque16(sigIn);

        if (signer != null)
        {
            byte[] sigByte = TlsUtils.readOpaque16(is);

            if (!signer.verifySignature(sigByte))
            {
                handler.failWithError(TlsProtocolHandler.AL_fatal,
                    TlsProtocolHandler.AP_bad_certificate);
            }
        }

        BigInteger p = new BigInteger(1, pBytes);
        BigInteger g = new BigInteger(1, gBytes);
        BigInteger Ys = new BigInteger(1, YsBytes);

        this.dhAgreeServerPublicKey = validateDHPublicKey(new DHPublicKeyParameters(Ys,
            new DHParameters(p, g)));
    }

//    private void processRSAServerKeyExchange(InputStream is, Signer signer) throws IOException
//    {
//        InputStream sigIn = is;
//        if (signer != null)
//        {
//            sigIn = new SignerInputStream(is, signer);
//        }
//
//        byte[] modulusBytes = TlsUtils.readOpaque16(sigIn);
//        byte[] exponentBytes = TlsUtils.readOpaque16(sigIn);
//
//        if (signer != null)
//        {
//            byte[] sigByte = TlsUtils.readOpaque16(is);
//
//            if (!signer.verifySignature(sigByte))
//            {
//                handler.failWithError(TlsProtocolHandler.AL_fatal,
//                    TlsProtocolHandler.AP_bad_certificate);
//            }
//        }
//
//        BigInteger modulus = new BigInteger(1, modulusBytes);
//        BigInteger exponent = new BigInteger(1, exponentBytes);
//
//        this.rsaServerPublicKey = validateRSAPublicKey(new RSAKeyParameters(false, modulus,
//            exponent));
//    }

    private DHPublicKeyParameters validateDHPublicKey(DHPublicKeyParameters key) throws IOException
    {
        BigInteger Y = key.getY();
        DHParameters params = key.getParameters();
        BigInteger p = params.getP();
        BigInteger g = params.getG();

        if (!p.isProbablePrime(2))
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_illegal_parameter);
        }
        if (g.compareTo(TWO) < 0 || g.compareTo(p.subtract(TWO)) > 0)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_illegal_parameter);
        }
        if (Y.compareTo(TWO) < 0 || Y.compareTo(p.subtract(ONE)) > 0)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_illegal_parameter);
        }

        // TODO See RFC 2631 for more discussion of Diffie-Hellman validation

        return key;
    }

    private RSAKeyParameters validateRSAPublicKey(RSAKeyParameters key) throws IOException
    {
        // TODO What is the minimum bit length required?
//        key.getModulus().bitLength();

        if (!key.getExponent().isProbablePrime(2))
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_illegal_parameter);
        }

        return key;
    }
}
