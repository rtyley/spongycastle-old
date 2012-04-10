package org.spongycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.crypto.params.DHPrivateKeyParameters;
import org.spongycastle.crypto.params.DHPublicKeyParameters;
import org.spongycastle.crypto.params.RSAKeyParameters;

class TlsPSKKeyExchange implements TlsKeyExchange
{
    protected TlsClientContext context;
    protected int keyExchange;
    protected TlsPSKIdentity pskIdentity;

    protected byte[] psk_identity_hint = null;

    protected DHPublicKeyParameters dhAgreeServerPublicKey = null;
    protected DHPrivateKeyParameters dhAgreeClientPrivateKey = null;

    protected RSAKeyParameters rsaServerPublicKey = null;
    protected byte[] premasterSecret;

    TlsPSKKeyExchange(TlsClientContext context, int keyExchange, TlsPSKIdentity pskIdentity)
    {
        switch (keyExchange)
        {
            case KeyExchangeAlgorithm.PSK:
            case KeyExchangeAlgorithm.RSA_PSK:
            case KeyExchangeAlgorithm.DHE_PSK:
                break;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }

        this.context = context;
        this.keyExchange = keyExchange;
        this.pskIdentity = pskIdentity;
    }

    public void skipServerCertificate() throws IOException
    {
        // OK
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void skipServerKeyExchange() throws IOException
    {
        this.psk_identity_hint = new byte[0];
    }

    public void processServerKeyExchange(InputStream is) throws IOException
    {
        this.psk_identity_hint = TlsUtils.readOpaque16(is);

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            byte[] pBytes = TlsUtils.readOpaque16(is);
            byte[] gBytes = TlsUtils.readOpaque16(is);
            byte[] YsBytes = TlsUtils.readOpaque16(is);

            BigInteger p = new BigInteger(1, pBytes);
            BigInteger g = new BigInteger(1, gBytes);
            BigInteger Ys = new BigInteger(1, YsBytes);

            this.dhAgreeServerPublicKey = TlsDHUtils.validateDHPublicKey(new DHPublicKeyParameters(Ys,
                new DHParameters(p, g)));
        }
        else if (this.psk_identity_hint.length == 0)
        {
            // TODO Should we enforce that this message should have been skipped if hint is empty?
//            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void skipClientCredentials() throws IOException
    {
    	// OK
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException
    {
    	if (psk_identity_hint == null || psk_identity_hint.length == 0)
    	{
    		pskIdentity.skipIdentityHint();
    	}
    	else
    	{
    		pskIdentity.notifyIdentityHint(psk_identity_hint);
    	}

    	byte[] psk_identity = pskIdentity.getPSKIdentity();

        TlsUtils.writeOpaque16(psk_identity, os);

        if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context,
                this.rsaServerPublicKey, os);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            this.dhAgreeClientPrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(
                context.getSecureRandom(), dhAgreeServerPublicKey.getParameters(), os);
        }
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        byte[] psk = pskIdentity.getPSK();
        byte[] other_secret = generateOtherSecret(psk.length);

        ByteArrayOutputStream buf = new ByteArrayOutputStream(4 + other_secret.length + psk.length);
        TlsUtils.writeOpaque16(other_secret, buf);
        TlsUtils.writeOpaque16(psk, buf);
        return buf.toByteArray();
    }

    protected byte[] generateOtherSecret(int pskLength)
    {
        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            return TlsDHUtils.calculateDHBasicAgreement(dhAgreeServerPublicKey, dhAgreeClientPrivateKey);
        }

        if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            return this.premasterSecret;
        }

        return new byte[pskLength];
    }
}
