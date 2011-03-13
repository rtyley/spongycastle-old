package org.spongycastle.crypto.tls;

import java.security.SecureRandom;

import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.DSA;
import org.spongycastle.crypto.Signer;
import org.spongycastle.crypto.digests.NullDigest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.DSADigestSigner;

abstract class TlsDSASigner implements TlsSigner
{
    public byte[] calculateRawSignature(SecureRandom secureRandom, AsymmetricKeyParameter privateKey, byte[] md5andsha1)
        throws CryptoException
    {
        // Note: Only use the SHA1 part of the hash
        Signer signer = new DSADigestSigner(createDSAImpl(), new NullDigest());
        signer.init(true, new ParametersWithRandom(privateKey, secureRandom));
        signer.update(md5andsha1, 16, 20);
        return signer.generateSignature();
    }

    public Signer createVerifyer(AsymmetricKeyParameter publicKey)
    {
        Signer verifyer = new DSADigestSigner(createDSAImpl(), new SHA1Digest());
        verifyer.init(false, publicKey);
        return verifyer;
    }

    protected abstract DSA createDSAImpl();
}
