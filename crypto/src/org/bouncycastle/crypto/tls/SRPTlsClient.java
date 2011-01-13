package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.util.Arrays;

class SRPTlsClient implements TlsClient
{
    private CertificateVerifyer verifyer;
    private byte[] identity;
    private byte[] password;

    private TlsClientContext context;

    private int selectedCipherSuite;

    SRPTlsClient(CertificateVerifyer verifyer, byte[] identity, byte[] password)
    {
        this.verifyer = verifyer;
        this.identity = Arrays.clone(identity);
        this.password = Arrays.clone(password);
    }

    public void init(TlsClientContext context)
    {
        this.context = context;
    }

    public int[] getCipherSuites()
    {
        return new int[] {
            CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
        };
    }

    public Hashtable generateClientExtensions() throws IOException
    {
        Hashtable clientExtensions = new Hashtable();
        ByteArrayOutputStream srpData = new ByteArrayOutputStream();
        TlsUtils.writeOpaque8(this.identity, srpData);

        clientExtensions.put(Integer.valueOf(ExtensionType.srp), srpData.toByteArray());
        return clientExtensions;
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
//            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public void processServerExtensions(Hashtable serverExtensions)
    {
        // TODO[SRP]
    }

    public TlsKeyExchange createKeyExchange() throws IOException
    {
        switch (selectedCipherSuite)
        {
            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
                return createSRPKeyExchange(KeyExchangeAlgorithm.SRP);

            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
                return createSRPKeyExchange(KeyExchangeAlgorithm.SRP_RSA);

            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
                return createSRPKeyExchange(KeyExchangeAlgorithm.SRP_DSS);

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher
                 * suites, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void processServerCertificateRequest(short[] certificateTypes,
        Vector certificateAuthorities) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.handshake_failure);
    }

    public Certificate getCertificate()
    {
        return null;
    }

    public byte[] generateCertificateSignature(byte[] md5andsha1) throws IOException
    {
        return null;
    }

    public TlsCipher createCipher() throws IOException
    {
        switch (selectedCipherSuite)
        {
            case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
                return createDESedeCipher(24);

            case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
                return createAESCipher(16);

            case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
                return createAESCipher(32);

            default:
                /*
                 * Note: internal error here; the TlsProtocolHandler verifies that the
                 * server-selected cipher suite was in the list of client-offered cipher
                 * suites, so if we now can't produce an implementation, we shouldn't have
                 * offered it!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    protected TlsKeyExchange createSRPKeyExchange(int keyExchange)
    {
        return new TlsSRPKeyExchange(context, verifyer, keyExchange, identity, password);
    }

    protected TlsCipher createAESCipher(int cipherKeySize)
    {
        return new TlsBlockCipher(context, createAESBlockCipher(),
            createAESBlockCipher(), createSHA1Digest(), createSHA1Digest(), cipherKeySize);
    }

    protected TlsCipher createDESedeCipher(int cipherKeySize)
    {
        return new TlsBlockCipher(context, createDESedeBlockCipher(),
            createDESedeBlockCipher(), createSHA1Digest(), createSHA1Digest(), cipherKeySize);
    }

    protected BlockCipher createAESBlockCipher()
    {
        return new CBCBlockCipher(new AESFastEngine());
    }

    protected BlockCipher createDESedeBlockCipher()
    {
        return new CBCBlockCipher(new DESedeEngine());
    }

    protected Digest createSHA1Digest()
    {
        return new SHA1Digest();
    }
}
