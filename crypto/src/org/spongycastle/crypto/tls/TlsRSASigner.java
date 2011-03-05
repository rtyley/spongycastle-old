package org.spongycastle.crypto.tls;

import java.security.SecureRandom;

import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.digests.NullDigest;
import org.spongycastle.crypto.encodings.PKCS1Encoding;
import org.spongycastle.crypto.engines.RSABlindedEngine;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.signers.GenericSigner;

class TlsRSASigner implements TlsSigner
{
    public byte[] calculateRawSignature(SecureRandom random, AsymmetricKeyParameter privateKey, byte[] md5andsha1)
        throws CryptoException
    {
        Signer sig = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), new NullDigest());
        sig.init(true, new ParametersWithRandom(privateKey, random));
        sig.update(md5andsha1, 0, md5andsha1.length);
        return sig.generateSignature();
    }

    public Signer createVerifyer(AsymmetricKeyParameter publicKey)
    {
        Signer s = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), new CombinedHash());
        s.init(false, publicKey);
        return s;
    }

    public boolean isValidPublicKey(AsymmetricKeyParameter publicKey)
    {
        return publicKey instanceof RSAKeyParameters && !publicKey.isPrivate();
    }
}
