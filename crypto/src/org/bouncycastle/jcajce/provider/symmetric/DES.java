package org.bouncycastle.jcajce.provider.symmetric;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;

import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.RFC3211WrapEngine;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.CFBBlockCipherMac;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;

public final class DES
{
    private DES()
    {
    }

    static public class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new DESEngine());
        }
    }

    static public class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new DESEngine()), 64);
        }
    }

    /**
     * DES   CFB8
     */
    public static class DESCFB8
        extends BaseMac
    {
        public DESCFB8()
        {
            super(new CFBBlockCipherMac(new DESEngine()));
        }
    }

    /**
     * DES64
     */
    public static class DES64
        extends BaseMac
    {
        public DES64()
        {
            super(new CBCBlockCipherMac(new DESEngine(), 64));
        }
    }

    /**
     * DES64with7816-4Padding
     */
    public static class DES64with7816d4
        extends BaseMac
    {
        public DES64with7816d4()
        {
            super(new CBCBlockCipherMac(new DESEngine(), 64, new ISO7816d4Padding()));
        }
    }
    
    public static class CBCMAC
        extends BaseMac
    {
        public CBCMAC()
        {
            super(new CBCBlockCipherMac(new DESEngine()));
        }
    }

    static public class CMAC
        extends BaseMac
    {
        public CMAC()
        {
            super(new CMac(new DESEngine()));
        }
    }

    public static class RFC3211
        extends BaseWrapCipher
    {
        public RFC3211()
        {
            super(new RFC3211WrapEngine(new DESEngine()), 8);
        }
    }

  /**
     * DES - the default for this is to generate a key in
     * a-b-a format that's 24 bytes long but has 16 bytes of
     * key material (the first 8 bytes is repeated as the last
     * 8 bytes). If you give it a size, you'll get just what you
     * asked for.
     */
    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("DES", 64, new DESKeyGenerator());
        }

        protected void engineInit(
            int             keySize,
            SecureRandom random)
        {
            super.engineInit(keySize, random);
        }

        protected SecretKey engineGenerateKey()
        {
            if (uninitialised)
            {
                engine.init(new KeyGenerationParameters(new SecureRandom(), defaultKeySize));
                uninitialised = false;
            }

            return new SecretKeySpec(engine.generateKey(), algName);
        }
    }

    static public class KeyFactory
        extends BaseSecretKeyFactory
    {
        public KeyFactory()
        {
            super("DES", null);
        }

        protected KeySpec engineGetKeySpec(
            SecretKey key,
            Class keySpec)
        throws InvalidKeySpecException
        {
            if (keySpec == null)
            {
                throw new InvalidKeySpecException("keySpec parameter is null");
            }
            if (key == null)
            {
                throw new InvalidKeySpecException("key parameter is null");
            }

            if (SecretKeySpec.class.isAssignableFrom(keySpec))
            {
                return new SecretKeySpec(key.getEncoded(), algName);
            }
            else if (DESKeySpec.class.isAssignableFrom(keySpec))
            {
                byte[]  bytes = key.getEncoded();

                try
                {
                    return new DESKeySpec(bytes);
                }
                catch (Exception e)
                {
                    throw new InvalidKeySpecException(e.toString());
                }
            }

            throw new InvalidKeySpecException("Invalid KeySpec");
        }

        protected SecretKey engineGenerateSecret(
            KeySpec keySpec)
        throws InvalidKeySpecException
        {
            if (keySpec instanceof DESKeySpec)
            {
                DESKeySpec desKeySpec = (DESKeySpec)keySpec;
                return new SecretKeySpec(desKeySpec.getKey(), "DES");
            }

            return super.engineGenerateSecret(keySpec);
        }
    }

    public static class Mappings
        extends HashMap
    {
        private static final String PREFIX = DES.class.getName();
                
        public Mappings()
        {
            put("Cipher.DES", PREFIX + "$ECB");
            put("Cipher." + OIWObjectIdentifiers.desCBC, PREFIX + "$CBC");

            addAlias(OIWObjectIdentifiers.desCBC, "DES");

            put("Cipher.DESRFC3211WRAP", PREFIX + "$RFC3211");

            put("KeyGenerator.DES", PREFIX + "$KeyGenerator");

            put("SecretKeyFactory.DES", PREFIX + "$KeyFactory");

            put("Mac.DESCMAC", PREFIX + "$CMAC");
            put("Mac.DESMAC", PREFIX + "$CBCMAC");
            put("Alg.Alias.Mac.DES", "DESMAC");

            put("Mac.DESMAC/CFB8", PREFIX + "$DESCFB8");
            put("Alg.Alias.Mac.DES/CFB8", "DESMAC/CFB8");

            put("Mac.DESMAC64", PREFIX + "$DES64");
            put("Alg.Alias.Mac.DES64", "DESMAC64");

            put("Mac.DESMAC64WITHISO7816-4PADDING", PREFIX + "$DES64with7816d4");
            put("Alg.Alias.Mac.DES64WITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
            put("Alg.Alias.Mac.DESISO9797ALG1MACWITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");
            put("Alg.Alias.Mac.DESISO9797ALG1WITHISO7816-4PADDING", "DESMAC64WITHISO7816-4PADDING");

            put("AlgorithmParameters.DES", DES.class.getPackage().getName() + ".util.IvAlgorithmParameters");
        }

        private void addAlias(ASN1ObjectIdentifier oid, String name)
        {
            put("Alg.Alias.KeyGenerator." + oid.getId(), name);
            put("Alg.Alias.KeyFactory." + oid.getId(), name);
        }
    }
}
