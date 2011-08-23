package org.bouncycastle.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.engines.RFC3211WrapEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class AES
{
    private AES()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new AESFastEngine());
        }
    }

    public static class CBC
       extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new AESFastEngine()), 128);
        }
    }

    static public class CFB
        extends BaseBlockCipher
    {
        public CFB()
        {
            super(new BufferedBlockCipher(new CFBBlockCipher(new AESFastEngine(), 128)), 128);
        }
    }

    static public class OFB
        extends BaseBlockCipher
    {
        public OFB()
        {
            super(new BufferedBlockCipher(new OFBBlockCipher(new AESFastEngine(), 128)), 128);
        }
    }

    public static class AESCMAC
        extends BaseMac
    {
        public AESCMAC()
        {
            super(new CMac(new AESFastEngine()));
        }
    }

    static public class Wrap
        extends BaseWrapCipher
    {
        public Wrap()
        {
            super(new AESWrapEngine());
        }
    }

    public static class RFC3211Wrap
        extends BaseWrapCipher
    {
        public RFC3211Wrap()
        {
            super(new RFC3211WrapEngine(new AESFastEngine()), 16);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            this(192);
        }

        public KeyGen(int keySize)
        {
            super("AES", keySize, new CipherKeyGenerator());
        }
    }

    public static class KeyGen128
        extends KeyGen
    {
        public KeyGen128()
        {
            super(128);
        }
    }

    public static class KeyGen192
        extends KeyGen
    {
        public KeyGen192()
        {
            super(192);
        }
    }

    public static class KeyGen256
        extends KeyGen
    {
        public KeyGen256()
        {
            super(256);
        }
    }

    public static class AlgParamGen
        extends BaseAlgorithmParameterGenerator
    {
        protected void engineInit(
            AlgorithmParameterSpec genParamSpec,
            SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for AES parameter generation.");
        }

        protected AlgorithmParameters engineGenerateParameters()
        {
            byte[]  iv = new byte[16];

            if (random == null)
            {
                random = new SecureRandom();
            }

            random.nextBytes(iv);

            AlgorithmParameters params;

            try
            {
                params = AlgorithmParameters.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
                params.init(new IvParameterSpec(iv));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.getMessage());
            }

            return params;
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "AES IV";
        }
    }

    public static class Mappings
        extends HashMap
    {
        private static final String PREFIX = AES.class.getName();
        
        /**
         * These three got introduced in some messages as a result of a typo in an
         * early document. We don't produce anything using these OID values, but we'll
         * read them.
         */
        private static final String wrongAES128 = "2.16.840.1.101.3.4.2";
        private static final String wrongAES192 = "2.16.840.1.101.3.4.22";
        private static final String wrongAES256 = "2.16.840.1.101.3.4.42";

        public Mappings()
        {
            put("AlgorithmParameters.AES", PREFIX + "$AlgParams");
            put("Alg.Alias.AlgorithmParameters." + wrongAES128, "AES");
            put("Alg.Alias.AlgorithmParameters." + wrongAES192, "AES");
            put("Alg.Alias.AlgorithmParameters." + wrongAES256, "AES");
            put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes128_CBC, "AES");
            put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes192_CBC, "AES");
            put("Alg.Alias.AlgorithmParameters." + NISTObjectIdentifiers.id_aes256_CBC, "AES");

            put("AlgorithmParameterGenerator.AES", PREFIX + "$AlgParamGen");
            put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES128, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES192, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + wrongAES256, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes128_CBC, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes192_CBC, "AES");
            put("Alg.Alias.AlgorithmParameterGenerator." + NISTObjectIdentifiers.id_aes256_CBC, "AES");

            put("Cipher.AES", PREFIX + "$ECB");
            put("Alg.Alias.Cipher." + wrongAES128, "AES");
            put("Alg.Alias.Cipher." + wrongAES192, "AES");
            put("Alg.Alias.Cipher." + wrongAES256, "AES");
            put("Cipher." + NISTObjectIdentifiers.id_aes128_ECB, PREFIX + "$ECB");
            put("Cipher." + NISTObjectIdentifiers.id_aes192_ECB, PREFIX + "$ECB");
            put("Cipher." + NISTObjectIdentifiers.id_aes256_ECB, PREFIX + "$ECB");
            put("Cipher." + NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "$CBC");
            put("Cipher." + NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "$CBC");
            put("Cipher." + NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "$CBC");
            put("Cipher." + NISTObjectIdentifiers.id_aes128_OFB, PREFIX + "$OFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes192_OFB, PREFIX + "$OFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes256_OFB, PREFIX + "$OFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes128_CFB, PREFIX + "$CFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes192_CFB, PREFIX + "$CFB");
            put("Cipher." + NISTObjectIdentifiers.id_aes256_CFB, PREFIX + "$CFB");
            put("Cipher.AESWRAP", PREFIX + "$Wrap");
            put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes128_wrap, "AESWRAP");
            put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes192_wrap, "AESWRAP");
            put("Alg.Alias.Cipher." + NISTObjectIdentifiers.id_aes256_wrap, "AESWRAP");
            put("Cipher.AESRFC3211WRAP", PREFIX + "$RFC3211Wrap");

            put("KeyGenerator.AES", PREFIX + "$KeyGen");
            put("KeyGenerator.2.16.840.1.101.3.4.2", PREFIX + "$KeyGen128");
            put("KeyGenerator.2.16.840.1.101.3.4.22", PREFIX + "$KeyGen192");
            put("KeyGenerator.2.16.840.1.101.3.4.42", PREFIX + "$KeyGen256");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_ECB, PREFIX + "$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_CBC, PREFIX + "$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_OFB, PREFIX + "$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_CFB, PREFIX + "$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_ECB, PREFIX + "$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_CBC, PREFIX + "$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_OFB, PREFIX + "$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_CFB, PREFIX + "$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_ECB, PREFIX + "$KeyGen256");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_CBC, PREFIX + "$KeyGen256");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_OFB, PREFIX + "$KeyGen256");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_CFB, PREFIX + "$KeyGen256");
            put("KeyGenerator.AESWRAP", PREFIX + "$KeyGen");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes128_wrap, PREFIX + "$KeyGen128");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes192_wrap, PREFIX + "$KeyGen192");
            put("KeyGenerator." + NISTObjectIdentifiers.id_aes256_wrap, PREFIX + "$KeyGen256");

            put("Mac.AESCMAC", PREFIX + "$AESCMAC");
        }
    }
}
