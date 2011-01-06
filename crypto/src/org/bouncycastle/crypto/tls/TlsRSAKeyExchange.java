package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

/**
 * TLS 1.0 RSA key exchange.
 */
class TlsRSAKeyExchange implements TlsKeyExchange
{
    protected TlsClientContext context;
    protected CertificateVerifyer verifyer;

    protected AsymmetricKeyParameter serverPublicKey = null;

    protected RSAKeyParameters rsaServerPublicKey = null;

    protected byte[] premasterSecret;

    TlsRSAKeyExchange(TlsClientContext context, CertificateVerifyer verifyer)
    {
        this.context = context;
        this.verifyer = verifyer;
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

        if (!(this.serverPublicKey instanceof RSAKeyParameters))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);
        this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters)this.serverPublicKey);

        /*
         * Verify them.
         */
        if (!this.verifyer.isValid(serverCertificate.getCerts()))
        {
            throw new TlsFatalAlert(AlertDescription.user_canceled);
        }
    }

    public void skipServerKeyExchange() throws IOException
    {
        // OK
    }

    public void processServerKeyExchange(InputStream is, SecurityParameters securityParameters)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException
    {
        /*
         * Choose a PremasterSecret and send it encrypted to the server
         */
        premasterSecret = new byte[48];
        context.getSecureRandom().nextBytes(premasterSecret);
        TlsUtils.writeVersion(premasterSecret, 0);

        PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
        encoding.init(true, new ParametersWithRandom(this.rsaServerPublicKey, context.getSecureRandom()));

        try
        {
            byte[] keData = encoding.processBlock(premasterSecret, 0, premasterSecret.length);
            TlsUtils.writeUint24(keData.length + 2, os);
            TlsUtils.writeOpaque16(keData, os);
        }
        catch (InvalidCipherTextException e)
        {
            /*
             * This should never happen, only during decryption.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        byte[] tmp = this.premasterSecret;
        this.premasterSecret = null;
        return tmp;
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

//    protected void processRSAServerKeyExchange(InputStream is, Signer signer) throws IOException
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
//                handler.failWithError(AlertLevel.fatal, AlertDescription.bad_certificate);
//            }
//        }
//
//        BigInteger modulus = new BigInteger(1, modulusBytes);
//        BigInteger exponent = new BigInteger(1, exponentBytes);
//
//        this.rsaServerPublicKey = validateRSAPublicKey(new RSAKeyParameters(false, modulus,
//            exponent));
//    }

    protected RSAKeyParameters validateRSAPublicKey(RSAKeyParameters key) throws IOException
    {
        // TODO What is the minimum bit length required?
//        key.getModulus().bitLength();

        if (!key.getExponent().isProbablePrime(2))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return key;
    }
}
