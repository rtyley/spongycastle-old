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

    private DHPublicKeyParameters dhServerPublicKey = null;
    private AsymmetricCipherKeyPair dhClientKeyPair = null;

    private byte[] pms;

    DefaultTlsKeyExchange(TlsProtocolHandler handler, CertificateVerifyer verifyer,
        short keyExchange)
    {
        switch (keyExchange)
        {
            case TlsKeyExchange.KE_RSA:
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
        if (tlsSigner != null)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_unexpected_message);
        }
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
        switch (this.keyExchange)
        {
            case TlsKeyExchange.KE_RSA:
                if (!(this.serverPublicKey instanceof RSAKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal,
                        TlsProtocolHandler.AP_certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);
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
        if (isServerKeyExchangeExpected())
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_unexpected_message);
        }
    }

    protected void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException
    {
        if (!isServerKeyExchangeExpected())
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_unexpected_message);
        }

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
                encoding.init(true, new ParametersWithRandom(this.serverPublicKey,
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
                    return null;
                }
            }

            case TlsKeyExchange.KE_DHE_DSS:
            case TlsKeyExchange.KE_DHE_RSA:
            {
                /*
                 * Generate a keypair and send the public value to the server
                 */
                DHBasicKeyPairGenerator dhGen = new DHBasicKeyPairGenerator();
                dhGen.init(new DHKeyGenerationParameters(handler.getRandom(),
                    dhServerPublicKey.getParameters()));
                this.dhClientKeyPair = dhGen.generateKeyPair();
                BigInteger Yc = ((DHPublicKeyParameters)dhClientKeyPair.getPublic()).getY();
                return BigIntegers.asUnsignedByteArray(Yc);
            }

            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal,
                    TlsProtocolHandler.AP_unexpected_message);
                return null;
        }
    }

    protected byte[] getPremasterSecret() throws IOException
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
                dhAgree.init(dhClientKeyPair.getPrivate());
                BigInteger agreement = dhAgree.calculateAgreement(dhServerPublicKey);
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

        /*
         * Parse the Structure
         */
        byte[] pByte = TlsUtils.readOpaque16(sigIn);
        byte[] gByte = TlsUtils.readOpaque16(sigIn);
        byte[] YsByte = TlsUtils.readOpaque16(sigIn);

        if (signer != null)
        {
            byte[] sigByte = TlsUtils.readOpaque16(is);

            /*
             * Verify the Signature.
             */
            if (!signer.verifySignature(sigByte))
            {
                handler.failWithError(TlsProtocolHandler.AL_fatal,
                    TlsProtocolHandler.AP_bad_certificate);
            }
        }

        /*
         * Do the DH calculation.
         */
        BigInteger p = new BigInteger(1, pByte);
        BigInteger g = new BigInteger(1, gByte);
        BigInteger Ys = new BigInteger(1, YsByte);

        /*
         * Check the DH parameter values
         */
        if (!p.isProbablePrime(10))
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_illegal_parameter);
        }
        if (g.compareTo(TWO) < 0 || g.compareTo(p.subtract(TWO)) > 0)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_illegal_parameter);
        }
        // TODO For static DH public values, see additional checks in RFC 2631 2.1.5 
        if (Ys.compareTo(TWO) < 0 || Ys.compareTo(p.subtract(ONE)) > 0)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal,
                TlsProtocolHandler.AP_illegal_parameter);
        }

        this.dhServerPublicKey = new DHPublicKeyParameters(Ys, new DHParameters(p, g));
    }

    private boolean isServerKeyExchangeExpected()
    {
        // RFC 2246 7.4.3.
        switch (this.keyExchange)
        {
            case KE_RSA:
            case KE_DH_DSS:
            case KE_DH_RSA:
                return false;

            default:
                return true;
        }
    }
}
