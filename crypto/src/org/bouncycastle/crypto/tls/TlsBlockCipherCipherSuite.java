package org.bouncycastle.crypto.tls;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
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
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A generic TLS 1.0 block cipher suite. This can be used for AES or 3DES for
 * example.
 */
class TlsBlockCipherCipherSuite extends TlsCipherSuite
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private TlsProtocolHandler handler;
    private CertificateVerifyer verifyer;

    private BlockCipher encryptCipher;
    private BlockCipher decryptCipher;

    private Digest writeDigest;
    private Digest readDigest;

    private TlsMac writeMac;
    private TlsMac readMac;

    private int cipherKeySize;
    private short keyExchange;

    private AsymmetricKeyParameter serverPublicKey = null;

    private BigInteger SRP_A = null;
    private byte[] SRP_identity = null;
    private byte[] SRP_password = null;

    private BigInteger Yc;
    private byte[] pms;

    protected TlsBlockCipherCipherSuite(TlsProtocolHandler handler, CertificateVerifyer verifyer,
        BlockCipher encrypt, BlockCipher decrypt,
        Digest writeDigest, Digest readDigest,
        int cipherKeySize, short keyExchange)
    {
        this.handler = handler;
        this.verifyer = verifyer;
        this.encryptCipher = encrypt;
        this.decryptCipher = decrypt;
        this.writeDigest = writeDigest;
        this.readDigest = readDigest;
        this.cipherKeySize = cipherKeySize;
        this.keyExchange = keyExchange;
    }

    protected TlsCipher createCipher(byte[] ms, byte[] cr, byte[] sr)
    {
        int prfSize = (2 * cipherKeySize) + writeDigest.getDigestSize() + readDigest.getDigestSize()
            + encryptCipher.getBlockSize() + decryptCipher.getBlockSize();
        byte[] key_block = new byte[prfSize];
        byte[] random = new byte[cr.length + sr.length];
        System.arraycopy(cr, 0, random, sr.length, cr.length);
        System.arraycopy(sr, 0, random, 0, sr.length);
        TlsUtils.PRF(ms, "key expansion", random, key_block);

        int offset = 0;

        // Init MACs
        writeMac = new TlsMac(writeDigest, key_block, offset, writeDigest
            .getDigestSize());
        offset += writeDigest.getDigestSize();
        readMac = new TlsMac(readDigest, key_block, offset, readDigest
            .getDigestSize());
        offset += readDigest.getDigestSize();

        // Init Ciphers
        this.initCipher(true, encryptCipher, key_block, cipherKeySize, offset,
            offset + (cipherKeySize * 2));
        offset += cipherKeySize;
        this.initCipher(false, decryptCipher, key_block, cipherKeySize, offset,
            offset + cipherKeySize + encryptCipher.getBlockSize());

        return new TlsCipherImpl();
    }

    private void initCipher(boolean forEncryption, BlockCipher cipher,
        byte[] key_block, int key_size, int key_offset, int iv_offset)
    {
        KeyParameter key_parameter = new KeyParameter(key_block, key_offset,
            key_size);
        ParametersWithIV parameters_with_iv = new ParametersWithIV(
            key_parameter, key_block, iv_offset, cipher.getBlockSize());
        cipher.init(forEncryption, parameters_with_iv);
    }

    private class TlsCipherImpl implements TlsCipher
    {
        public byte[] encodePlaintext(short type, byte[] plaintext, int offset, int len)
        {
            int blocksize = encryptCipher.getBlockSize();

            // Add a random number of extra blocks worth of padding
            int minPaddingSize = blocksize
                    - ((len + writeMac.getSize() + 1) % blocksize);
            int maxExtraPadBlocks = (255 - minPaddingSize) / blocksize;
            int actualExtraPadBlocks = chooseExtraPadBlocks(
                    handler.getRandom(), maxExtraPadBlocks);
            int paddingsize = minPaddingSize
                    + (actualExtraPadBlocks * blocksize);

            int totalsize = len + writeMac.getSize() + paddingsize + 1;
            byte[] outbuf = new byte[totalsize];
            System.arraycopy(plaintext, offset, outbuf, 0, len);
            byte[] mac = writeMac.calculateMac(type, plaintext, offset, len);
            System.arraycopy(mac, 0, outbuf, len, mac.length);
            int paddoffset = len + mac.length;
            for (int i = 0; i <= paddingsize; i++)
            {
                outbuf[i + paddoffset] = (byte) paddingsize;
            }
            for (int i = 0; i < totalsize; i += blocksize)
            {
                encryptCipher.processBlock(outbuf, i, outbuf, i);
            }
            return outbuf;

        }

        public byte[] decodeCiphertext(short type, byte[] ciphertext, int offset, int len) throws IOException
        {
            // TODO TLS 1.1 (RFC 4346) introduces an explicit IV

            int minLength = readMac.getSize() + 1;
            int blocksize = decryptCipher.getBlockSize();
            boolean decrypterror = false;

            /*
             * ciphertext must be at least (macsize + 1) bytes long
             */
            if (len < minLength)
            {
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_decode_error);
            }

            /*
             * ciphertext must be a multiple of blocksize
             */
            if (len % blocksize != 0)
            {
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_decryption_failed);
            }

            /*
             * Decrypt all the ciphertext using the blockcipher
             */
            for (int i = 0; i < len; i += blocksize)
            {
                decryptCipher.processBlock(ciphertext, i + offset, ciphertext, i + offset);
            }

            /*
             * Check if padding is correct
             */
            int lastByteOffset = offset + len - 1;

            byte paddingsizebyte = ciphertext[lastByteOffset];

            // Note: interpret as unsigned byte
            int paddingsize = paddingsizebyte & 0xff;

            int maxPaddingSize = len - minLength;
            if (paddingsize > maxPaddingSize)
            {
                decrypterror = true;
                paddingsize = 0;
            }
            else
            {
                /*
                 * Now, check all the padding-bytes (constant-time comparison).
                 */
                byte diff = 0;
                for (int i = lastByteOffset - paddingsize; i < lastByteOffset; ++i)
                {
                    diff |= (ciphertext[i] ^ paddingsizebyte);
                }
                if (diff != 0)
                {
                    /* Wrong padding */
                    decrypterror = true;
                    paddingsize = 0;
                }
            }

            /*
             * We now don't care if padding verification has failed or not, we
             * will calculate the mac to give an attacker no kind of timing
             * profile he can use to find out if mac verification failed or
             * padding verification failed.
             */
            int plaintextlength = len - minLength - paddingsize;
            byte[] calculatedMac = readMac.calculateMac(type, ciphertext, offset, plaintextlength);

            /*
             * Check all bytes in the mac (constant-time comparison).
             */
            byte[] decryptedMac = new byte[calculatedMac.length];
            System.arraycopy(ciphertext, offset + plaintextlength, decryptedMac, 0, calculatedMac.length);

            if (!Arrays.constantTimeAreEqual(calculatedMac, decryptedMac))
            {
                decrypterror = true;
            }

            /*
             * Now, it is safe to fail.
             */
            if (decrypterror)
            {
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_bad_record_mac);
            }

            byte[] plaintext = new byte[plaintextlength];
            System.arraycopy(ciphertext, offset, plaintext, 0, plaintextlength);
            return plaintext;
        }
    }

    private int chooseExtraPadBlocks(SecureRandom r, int max)
    {
//        return r.nextInt(max + 1);

        int x = r.nextInt();
        int n = lowestBitSet(x);
        return Math.min(n, max);
    }

    private int lowestBitSet(int x)
    {
        if (x == 0)
        {
            return 32;
        }

        int n = 0;
        while ((x & 1) == 0)
        {
            ++n;
            x >>= 1;
        }
        return n;
    }

    protected void skipServerCertificate() throws IOException
    {
      if (this.keyExchange != TlsCipherSuite.KE_SRP)
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
            case TlsCipherSuite.KE_RSA:
                if (!(this.serverPublicKey instanceof RSAKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);
                break;
            case TlsCipherSuite.KE_DHE_RSA:
            case TlsCipherSuite.KE_SRP_RSA:
                if (!(this.serverPublicKey instanceof RSAKeyParameters))
                {
                    handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_certificate_unknown);
                }
                validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
                break;
            case TlsCipherSuite.KE_DHE_DSS:
            case TlsCipherSuite.KE_SRP_DSS:
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

    protected void processServerKeyExchange(InputStream is,
        byte[] cr, byte[] sr) throws IOException
    {
        switch (this.keyExchange)
        {
            case TlsCipherSuite.KE_DHE_RSA:
            {
                processDHEKeyExchange(is, new TlsRSASigner(), cr, sr);
                break;
            }
            case TlsCipherSuite.KE_DHE_DSS:
            {
                processDHEKeyExchange(is, new TlsDSSSigner(), cr, sr);
                break;
            }
            case TlsCipherSuite.KE_SRP:
            {
                processSRPKeyExchange(is, null, null, null);
                break;
            }
            case TlsCipherSuite.KE_SRP_RSA:
            {
                processSRPKeyExchange(is, new TlsRSASigner(), cr, sr);
                break;
            }
            case TlsCipherSuite.KE_SRP_DSS:
            {
                processSRPKeyExchange(is, new TlsDSSSigner(), cr, sr);
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
            case TlsCipherSuite.KE_RSA:
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

            case TlsCipherSuite.KE_DHE_DSS:
            case TlsCipherSuite.KE_DHE_RSA:
                return BigIntegers.asUnsignedByteArray(this.Yc);

            case TlsCipherSuite.KE_SRP:
            case TlsCipherSuite.KE_SRP_RSA:
            case TlsCipherSuite.KE_SRP_DSS:
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

    private void processDHEKeyExchange(InputStream is, TlsSigner tlsSigner, byte[] cr, byte[] sr)
        throws IOException
    {
        InputStream sigIn = is;
        Signer signer = null;
        if (tlsSigner != null)
        {
            signer = tlsSigner.createSigner();
            signer.init(false, this.serverPublicKey);
            signer.update(cr, 0, cr.length);
            signer.update(sr, 0, sr.length);

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

    private void processSRPKeyExchange(InputStream is, TlsSigner tlsSigner, byte[] cr, byte[] sr)
        throws IOException
    {
        InputStream sigIn = is;
        Signer signer = null;
        if (tlsSigner != null)
        {
            signer = tlsSigner.createSigner();
            signer.init(false, this.serverPublicKey);
            signer.update(cr, 0, cr.length);
            signer.update(sr, 0, sr.length);

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
