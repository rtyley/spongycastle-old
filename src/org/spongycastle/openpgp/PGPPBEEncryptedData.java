package org.spongycastle.openpgp;

import org.spongycastle.bcpg.BCPGInputStream;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.InputStreamPacket;
import org.spongycastle.bcpg.SymmetricEncIntegrityPacket;
import org.spongycastle.bcpg.SymmetricKeyEncSessionPacket;

import java.io.EOFException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A password based encryption object.
 */
public class PGPPBEEncryptedData
    extends PGPEncryptedData
{
    SymmetricKeyEncSessionPacket    keyData;
    
    PGPPBEEncryptedData(
        SymmetricKeyEncSessionPacket    keyData,
        InputStreamPacket               encData)
    {
        super(encData);
        
        this.keyData = keyData;
    }
    
    /**
     * Return the raw input stream for the data stream.
     * 
     * @return InputStream
     */
    public InputStream getInputStream()
    {
        return encData.getInputStream();
    }

    /**
     * Return the decrypted input stream, using the passed in passPhrase.
     *
     * @param passPhrase
     * @param provider
     * @return InputStream
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public InputStream getDataStream(
        char[]                passPhrase,
        String                provider)
        throws PGPException, NoSuchProviderException
    {
        return getDataStream(passPhrase, PGPUtil.getProvider(provider));
    }

    /**
     * Return the decrypted input stream, using the passed in passPhrase.
     * 
     * @param passPhrase
     * @param provider
     * @return InputStream
     * @throws PGPException
     */
    public InputStream getDataStream(
        char[]                passPhrase,
        Provider              provider)
        throws PGPException
    {
        try
        {
            int          keyAlgorithm = keyData.getEncAlgorithm();
            SecretKey    key = PGPUtil.makeKeyFromPassPhrase(keyAlgorithm, keyData.getS2K(), passPhrase, provider);

            byte[] secKeyData = keyData.getSecKeyData();
            if (secKeyData != null && secKeyData.length > 0)
            {
                Cipher keyCipher = Cipher.getInstance(
                    PGPUtil.getSymmetricCipherName(keyAlgorithm) + "/CFB/NoPadding",
                    provider);

                keyCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[keyCipher.getBlockSize()]));

                byte[] keyBytes = keyCipher.doFinal(secKeyData);

                keyAlgorithm = keyBytes[0];
                key = new SecretKeySpec(keyBytes, 1, keyBytes.length - 1, PGPUtil.getSymmetricCipherName(keyAlgorithm));
            }

            Cipher c = createStreamCipher(keyAlgorithm, provider);

            byte[] iv = new byte[c.getBlockSize()];

            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            encStream = new BCPGInputStream(new CipherInputStream(encData.getInputStream(), c));

            if (encData instanceof SymmetricEncIntegrityPacket)
            {
                truncStream = new TruncatedStream(encStream);

                String digestName = PGPUtil.getDigestName(HashAlgorithmTags.SHA1);
                MessageDigest digest = MessageDigest.getInstance(digestName, provider);

                encStream = new DigestInputStream(truncStream, digest);
            }

            for (int i = 0; i != iv.length; i++)
            {
                int    ch = encStream.read();

                if (ch < 0)
                {
                    throw new EOFException("unexpected end of stream.");
                }

                iv[i] = (byte)ch;
            }

            int    v1 = encStream.read();
            int    v2 = encStream.read();

            if (v1 < 0 || v2 < 0)
            {
                throw new EOFException("unexpected end of stream.");
            }


            // Note: the oracle attack on "quick check" bytes is not deemed
            // a security risk for PBE (see PGPPublicKeyEncryptedData)

            boolean repeatCheckPassed = iv[iv.length - 2] == (byte) v1
                    && iv[iv.length - 1] == (byte) v2;

            // Note: some versions of PGP appear to produce 0 for the extra
            // bytes rather than repeating the two previous bytes
            boolean zeroesCheckPassed = v1 == 0 && v2 == 0;

            if (!repeatCheckPassed && !zeroesCheckPassed)
            {
                throw new PGPDataValidationException("data check failed.");
            }

            return encStream;
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }

    private Cipher createStreamCipher(int keyAlgorithm, Provider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException,
            PGPException
    {
        String mode = (encData instanceof SymmetricEncIntegrityPacket)
            ?   "CFB"
            :   "OpenPGPCFB";

        String cName = PGPUtil.getSymmetricCipherName(keyAlgorithm)
            + "/" + mode + "/NoPadding";

        return Cipher.getInstance(cName, provider);
    }
}
