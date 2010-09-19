package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.crypto.BlockCipher;
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
    private CertificateVerifyer verifyer;

    private TlsProtocolHandler handler;

    // (Optional) details for client-side authentication
    private Certificate clientCert = new Certificate(new X509CertificateStructure[0]);
    private AsymmetricKeyParameter clientPrivateKey = null;
    private TlsSigner clientSigner = null;

    private int selectedCipherSuite;

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

    public void init(TlsProtocolHandler handler)
    {
        this.handler = handler;
    }

    public int[] getCipherSuites()
    {
        return new int[] {
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,

//            CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
//            CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
//            CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
//            CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
//            CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
//            CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,

//            CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
//            CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
//            CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
//            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
//            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
//            CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
//            CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
//            CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
//            CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
        };
    }

    public Hashtable generateClientExtensions()
    {
        // TODO[SRP]
//        Hashtable clientExtensions = new Hashtable();
//        ByteArrayOutputStream srpData = new ByteArrayOutputStream();
//        TlsUtils.writeOpaque8(SRP_identity, srpData);
//
//        clientExtensions.put(Integer.valueOf(ExtensionType.srp), srpData.toByteArray());
//        return clientExtensions;
        return null;
    }

    public short[] getCompressionMethods()
    {
        return new short[] { CompressionMethod.NULL };
    }

    public void notifySessionID(byte[] sessionID)
    {
        // Currently ignored 
    }

    public void notifySelectedCipherSuite(int selectedCipherSuite)
    {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public void notifySelectedCompressionMethod(short selectedCompressionMethod)
    {
        // TODO Store and use
    }

    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
    {
        if (!secureRenegotiation)
        {
            /*
             * RFC 5746 3.4. If the extension is not present, the server does not support
             * secure renegotiation; set secure_renegotiation flag to FALSE. In this case,
             * some clients may want to terminate the handshake instead of continuing; see
             * Section 4.1 for discussion.
             */
//            handler.failWithError(AlertLevel.fatal,
//                TlsProtocolHandler.AP_handshake_failure);
        }
    }

    public void processServerExtensions(Hashtable serverExtensions)
    {
        // TODO Validate/process serverExtensions (via client?)
        // TODO[SRP]
    }

    public TlsKeyExchange createKeyExchange() throws IOException
    {
        switch (selectedCipherSuite)
        {
            case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
                return createRSAKeyExchange();

            case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
                return createDHKeyExchange(TlsKeyExchange.KE_DH_DSS);

            case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
                return createDHKeyExchange(TlsKeyExchange.KE_DH_RSA);

            case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
                return createDHKeyExchange(TlsKeyExchange.KE_DHE_DSS);

            case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
                return createDHKeyExchange(TlsKeyExchange.KE_DHE_RSA);

            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
                return createSRPExchange(TlsKeyExchange.KE_SRP);

            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
                return createSRPExchange(TlsKeyExchange.KE_SRP_RSA);

            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
                return createSRPExchange(TlsKeyExchange.KE_SRP_DSS);

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher
                 * suites, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                handler.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
                return null; // Unreachable!
        }
    }

    public void processServerCertificateRequest(short[] certificateTypes,
        Vector certificateAuthorities)
    {
        // TODO There shouldn't be a certificate request for SRP 

        // TODO Use provided info to choose a certificate in getCertificate()
    }

    public byte[] generateCertificateSignature(byte[] md5andsha1) throws IOException
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
            handler.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
            return null;
        }
    }

    public Certificate getCertificate()
    {
        return clientCert;
    }

    public TlsCipher createCipher(SecurityParameters securityParameters) throws IOException
    {
        switch (selectedCipherSuite)
        {
            case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
                return createDESedeCipher(24, securityParameters);

            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
                return createAESCipher(16, securityParameters);

            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
                return createAESCipher(32, securityParameters);

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher
                 * suites, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                handler.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
                return null; // Unreachable!
        }
    }

    private TlsKeyExchange createDHKeyExchange(short keyExchange)
    {
        return new TlsDHKeyExchange(handler, verifyer, keyExchange);
    }

    private TlsKeyExchange createRSAKeyExchange()
    {
        return new TlsRSAKeyExchange(handler, verifyer);
    }

    private TlsKeyExchange createSRPExchange(short keyExchange)
    {
        return new TlsSRPKeyExchange(handler, verifyer, keyExchange);
    }

    private TlsCipher createAESCipher(int cipherKeySize, SecurityParameters securityParameters)
    {
        return new TlsBlockCipher(handler, createAESBlockCipher(), createAESBlockCipher(),
            new SHA1Digest(), new SHA1Digest(), cipherKeySize, securityParameters);
    }

    private TlsCipher createDESedeCipher(int cipherKeySize, SecurityParameters securityParameters)
    {
        return new TlsBlockCipher(handler, createDESedeBlockCipher(), createDESedeBlockCipher(),
            new SHA1Digest(), new SHA1Digest(), cipherKeySize, securityParameters);
    }

    private static BlockCipher createAESBlockCipher()
    {
        return new CBCBlockCipher(new AESFastEngine());
    }

    private static BlockCipher createDESedeBlockCipher()
    {
        return new CBCBlockCipher(new DESedeEngine());
    }
}
