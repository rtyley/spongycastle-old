package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

class DefaultTlsClient implements TlsClient
{
    // TODO Add runtime support for this check?
    /* RFC 2246 9.
     * In the absence of an application profile standard specifying
     * otherwise, a TLS compliant application MUST implement the cipher
     * suite TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA.
     */
    private static final int TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a;
    private static final int TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013;
    private static final int TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016;
    private static final int TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f;
    private static final int TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032;
    private static final int TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033;
    private static final int TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035;
    private static final int TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038;
    private static final int TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039;

//    private static final int TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A;    
//    private static final int TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B;
//    private static final int TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C;
//    private static final int TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D;
//    private static final int TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E;
//    private static final int TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F;
//    private static final int TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020;
//    private static final int TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021;
//    private static final int TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022;
    
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

    public TlsCipherSuite createCipherSuite(int cipherSuite, TlsProtocolHandler handler)
        throws IOException
    {
        switch (cipherSuite)
        {
            case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
                return createDESedeCipherSuite(24, TlsCipherSuite.KE_DHE_RSA);

            case TLS_RSA_WITH_AES_128_CBC_SHA:
                return createAESCipherSuite(16, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
                return createAESCipherSuite(16, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
                return createAESCipherSuite(16, TlsCipherSuite.KE_DHE_RSA);

            case TLS_RSA_WITH_AES_256_CBC_SHA:
                return createAESCipherSuite(32, TlsCipherSuite.KE_RSA);

            case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                return createAESCipherSuite(32, TlsCipherSuite.KE_DHE_DSS);

            case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                return createAESCipherSuite(32, TlsCipherSuite.KE_DHE_RSA);

//            case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
//                return createDESedeCipherSuite(24, TlsCipherSuite.KE_SRP_DSS);
//
//            case TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
//                return createAESCipherSuite(16, TlsCipherSuite.KE_SRP_DSS);
//
//            case TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP);
//
//            case TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP_RSA);
//
//            case TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
//                return createAESCipherSuite(32, TlsCipherSuite.KE_SRP_DSS);

            default:
                // Note: internal error here; the TlsProtocolHandler verifies that the server-selected
                // cipher suite was in the list of client-offered cipher suites, so if we now can't
                // produce an implementation, we shouldn't have offered it!
                handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_internal_error);

                /*
                * Unreachable Code, failWithError will always throw an exception!
                */
                return null;
        }
    }

    public CertificateVerifyer getCertificateVerifyer()
    {
        return verifyer;
    }

    public byte[] generateCertificateSignature(byte[] md5andsha1, TlsProtocolHandler handler)
        throws IOException
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
            handler.failWithError(TlsProtocolHandler.AL_fatal, TlsProtocolHandler.AP_internal_error);
            return null;
        }
    }

    public Certificate getCertificate()
    {
        return clientCert;
    }

    public int[] getCipherSuites()
    {
        return new int[] {
           TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
           TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
           TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
           TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
           TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
           TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
           TLS_RSA_WITH_AES_256_CBC_SHA,
           TLS_RSA_WITH_AES_128_CBC_SHA,
           TLS_RSA_WITH_3DES_EDE_CBC_SHA,

//           TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
//           TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
//           TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
//           TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
//           TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
//           TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
//           TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
//           TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
//           TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
       };
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

    private static TlsCipherSuite createAESCipherSuite(int cipherKeySize, short keyExchange)
    {
        return new TlsBlockCipherCipherSuite(createAESCipher(), createAESCipher(),
            new SHA1Digest(), new SHA1Digest(), cipherKeySize, keyExchange);
    }

    private static TlsCipherSuite createDESedeCipherSuite(int cipherKeySize, short keyExchange)
    {
        return new TlsBlockCipherCipherSuite(createDESedeCipher(), createDESedeCipher(),
            new SHA1Digest(), new SHA1Digest(), cipherKeySize, keyExchange);
    }

    private static CBCBlockCipher createAESCipher()
    {
        return new CBCBlockCipher(new AESFastEngine());
    }
    
    private static CBCBlockCipher createDESedeCipher()
    {
        return new CBCBlockCipher(new DESedeEngine());
    }
}
