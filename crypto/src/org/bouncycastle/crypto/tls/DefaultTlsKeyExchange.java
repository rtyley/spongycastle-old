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
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.digests.SHA1Digest;
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

    private AsymmetricKeyParameter serverPublicKey = null;

    private BigInteger SRP_A = null;
    private byte[] SRP_identity = null;
    private byte[] SRP_password = null;

    private BigInteger Yc;
    private byte[] pms;

    DefaultTlsKeyExchange(TlsProtocolHandler handler, CertificateVerifyer verifyer, short keyExchange)
    {
        this.handler = handler;
        this.verifyer = verifyer;
        this.keyExchange = keyExchange;
    }

    protected void skipServerCertificate() throws IOException
    {
        if (this.keyExchange != TlsKeyExchange.KE_SRP)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unexpected_message);
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
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unsupported_certificate);
        }

        // Sanity check the PublicKeyFactory
        if (this.serverPublicKey.isPrivate())
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_internal_error);
        }

        /*
         * Perform various checks per RFC2246 7.4.2
         * TODO "Unless otherwise specified, the signing algorithm for the certificate
         * must be the same as the algorithm for the certificate key."
         */
        switch (this.keyExchange)
        {
            case TlsKeyExchange.KE_RSA:
                if (!(this.serverPublicKey instanceof RSAKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);
                break;
            case TlsKeyExchange.KE_DHE_RSA:
            case TlsKeyExchange.KE_SRP_RSA:
                if (!(this.serverPublicKey instanceof RSAKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                break;
            case TlsKeyExchange.KE_DHE_DSS:
            case TlsKeyExchange.KE_SRP_DSS:
                if (!(this.serverPublicKey instanceof DSAPublicKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_certificate_unknown);
                }
                break;
            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unsupported_certificate);
        }

        /*
         * Verify them.
         */
        if (!this.verifyer.isValid(serverCertificate.getCerts()))
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_user_canceled);
        }
    }

    protected void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException
    {
        switch (this.keyExchange)
        {
            case TlsKeyExchange.KE_DHE_RSA:
            {
                processDHEServerKeyExchange(is, initSigner(new TlsRSASigner(), securityParameters));
                break;
            }
            case TlsKeyExchange.KE_DHE_DSS:
            {
                processDHEServerKeyExchange(is, initSigner(new TlsDSSSigner(), securityParameters));
                break;
            }
            case TlsKeyExchange.KE_SRP:
            {
                processSRPServerKeyExchange(is, null);
                break;
            }
            case TlsKeyExchange.KE_SRP_RSA:
            {
                processSRPServerKeyExchange(is, initSigner(new TlsRSASigner(), securityParameters));
                break;
            }
            case TlsKeyExchange.KE_SRP_DSS:
            {
                processSRPServerKeyExchange(is, initSigner(new TlsDSSSigner(), securityParameters));
                break;
            }
            default:
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unexpected_message);
        }
    }

    protected void skipServerKeyExchange() throws IOException
    {
        /* RFC 2246 7.4.3. Server key exchange message
         * "It is not legal to send the server key exchange message for the
         * following key exchange methods:
         *
         * RSA
         * RSA_EXPORT (when the public key in the server certificate is
         *   less than or equal to 512 bits in length)
         * DH_DSS
         * DH_RSA
         */
        switch (this.keyExchange)
        {
        case KE_RSA:
        case KE_DH_DSS:
        case KE_DH_RSA:
            // No problem
            return;

        case KE_RSA_EXPORT:
            if (this.serverPublicKey instanceof RSAKeyParameters)
            {
                RSAKeyParameters rsaPubKey = (RSAKeyParameters)this.serverPublicKey;
                if (rsaPubKey.getModulus().bitLength() <= 512)
                {
                    return;
                }
            }
            break;
        }

        handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unexpected_message);
    }

    protected byte[] generateClientKeyExchange()
        throws IOException
    {
        switch (this.keyExchange)
        {
            case TlsKeyExchange.KE_RSA:
            {
                /*
                * We are doing RSA key exchange. We will
                * choose a pre master secret and send it
                * rsa encrypted to the server.
                *
                * Prepare pre master secret.
                */
                pms = new byte[48];
                handler.getRandom().nextBytes(pms);
                TlsUtils.writeVersion(pms, 0);

                /*
                * Encode the pms and send it to the server.
                *
                * Prepare an PKCS1Encoding with good random
                * padding.
                */
                PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
                encoding.init(true, new ParametersWithRandom(this.serverPublicKey, handler.getRandom()));

                try
                {
                    return encoding.processBlock(pms, 0, pms.length);
                }
                catch (InvalidCipherTextException e)
                {
                    /*
                    * This should never happen, only during decryption.
                    */
                    handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_internal_error);
                    return null;
                }
            }

            case TlsKeyExchange.KE_DHE_DSS:
            case TlsKeyExchange.KE_DHE_RSA:
                return BigIntegers.asUnsignedByteArray(this.Yc);

            case TlsKeyExchange.KE_SRP:
            case TlsKeyExchange.KE_SRP_RSA:
            case TlsKeyExchange.KE_SRP_DSS:
                return BigIntegers.asUnsignedByteArray(this.SRP_A);

            default:
                /*
                * Problem during handshake, we don't know
                * how to handle this key exchange method.
                */
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_unexpected_message);
                return null;
        }
    }

    protected byte[] getPremasterSecret()
    {
        return this.pms;
    }

    private void validateKeyUsage(X509CertificateStructure c, int keyUsageBits)
        throws IOException
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
                    handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_certificate_unknown);
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

    private void processDHEServerKeyExchange(InputStream is, Signer signer) throws IOException
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
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_bad_certificate);
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
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_illegal_parameter);
        }
        if (g.compareTo(TWO) < 0 || g.compareTo(p.subtract(TWO)) > 0)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_illegal_parameter);
        }
        // TODO For static DH public values, see additional checks in RFC 2631 2.1.5 
        if (Ys.compareTo(TWO) < 0 || Ys.compareTo(p.subtract(ONE)) > 0)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_illegal_parameter);
        }

        /*
         * Diffie-Hellman basic key agreement
         */
        DHParameters dhParams = new DHParameters(p, g);

        // Generate a keypair
        DHBasicKeyPairGenerator dhGen = new DHBasicKeyPairGenerator();
        dhGen.init(new DHKeyGenerationParameters(handler.getRandom(), dhParams));

        AsymmetricCipherKeyPair dhPair = dhGen.generateKeyPair();

        // Store the public value to send to server
        this.Yc = ((DHPublicKeyParameters)dhPair.getPublic()).getY();

        // Calculate the shared secret
        DHBasicAgreement dhAgree = new DHBasicAgreement();
        dhAgree.init(dhPair.getPrivate());

        BigInteger agreement = dhAgree.calculateAgreement(new DHPublicKeyParameters(Ys, dhParams));

        this.pms = BigIntegers.asUnsignedByteArray(agreement);
    }

    private void processSRPServerKeyExchange(InputStream is, Signer signer) throws IOException
    {
        InputStream sigIn = is;
        if (signer != null)
        {
            sigIn = new SignerInputStream(is, signer);
        }

        /*
         * Parse the Structure
         */
        byte[] NByte = TlsUtils.readOpaque16(sigIn);
        byte[] gByte = TlsUtils.readOpaque16(sigIn);
        byte[] sByte = TlsUtils.readOpaque8(sigIn);
        byte[] BByte = TlsUtils.readOpaque16(sigIn);
    
        if (signer != null)
        {
            byte[] sigByte = TlsUtils.readOpaque16(is);

            /*
             * Verify the Signature.
             */
            if (!signer.verifySignature(sigByte))
            {
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_bad_certificate);
            }
        }

        BigInteger N = new BigInteger(1, NByte);
        BigInteger g = new BigInteger(1, gByte);
        byte[] s = sByte;
        BigInteger B = new BigInteger(1, BByte);

        SRP6Client srpClient = new SRP6Client();
        srpClient.init(N, g, new SHA1Digest(), handler.getRandom());

        this.SRP_A = srpClient.generateClientCredentials(s, this.SRP_identity,
            this.SRP_password);

        try
        {
            BigInteger S = srpClient.calculateSecret(B);

            // TODO Check if this needs to be a fixed size
            this.pms = BigIntegers.asUnsignedByteArray(S);
        }
        catch (CryptoException e)
        {
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_illegal_parameter);
        }
    }
}
