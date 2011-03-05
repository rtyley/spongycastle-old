package org.spongycastle.jce.provider.asymmetric.ec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.JCEECPrivateKey;
import org.spongycastle.jce.provider.JCEECPublicKey;
import org.spongycastle.jce.provider.JDKKeyPairGenerator;
import org.spongycastle.jce.provider.ProviderUtil;
import org.spongycastle.jce.spec.ECParameterSpec;

public abstract class KeyPairGenerator
    extends JDKKeyPairGenerator
{
    public KeyPairGenerator(String algorithmName)
    {
        super(algorithmName);
    }

    public static class EC
        extends KeyPairGenerator
    {
        ECKeyGenerationParameters   param;
        ECKeyPairGenerator          engine = new ECKeyPairGenerator();
        ECParameterSpec             ecParams = null;
        int                         strength = 239;
        int                         certainty = 50;
        SecureRandom                random = new SecureRandom();
        boolean                     initialised = false;
        String                      algorithm;

        static private Hashtable    ecParameters;

        static {
            ecParameters = new Hashtable();

            ecParameters.put(new Integer(192),
                    ECNamedCurveTable.getParameterSpec("prime192v1"));
            ecParameters.put(new Integer(239),
                    ECNamedCurveTable.getParameterSpec("prime239v1"));
            ecParameters.put(new Integer(256),
                    ECNamedCurveTable.getParameterSpec("prime256v1"));
        }

        public EC()
        {
            super("EC");
            this.algorithm = "EC";
        }

        public EC(
            String  algorithm)
        {
            super(algorithm);
            this.algorithm = algorithm;
        }

        public void initialize(
            int             strength,
            SecureRandom    random)
        {
            this.strength = strength;
            this.random = random;
            this.ecParams = (ECParameterSpec)ecParameters.get(new Integer(strength));

            if (ecParams != null)
            {
                param = new ECKeyGenerationParameters(new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN()), random);

                engine.init(param);
                initialised = true;
            }
            else
            {
                throw new InvalidParameterException("unknown key size.");
            }
        }

        public void initialize(
            AlgorithmParameterSpec  params,
            SecureRandom            random)
            throws InvalidAlgorithmParameterException
        {
            if (params instanceof ECParameterSpec)
            {
                ECParameterSpec p = (ECParameterSpec)params;
                this.ecParams = (ECParameterSpec)params;

                param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN()), random);

                engine.init(param);
                initialised = true;
            }
            else if (params == null && ProviderUtil.getEcImplicitlyCa() != null)
            {
                ECParameterSpec p = ProviderUtil.getEcImplicitlyCa();
                this.ecParams = (ECParameterSpec)params;

                param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN()), random);

                engine.init(param);
                initialised = true;
            }
            else if (params == null && ProviderUtil.getEcImplicitlyCa() == null)
            {
                throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
            }
            else
            {
                throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec");
            }
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised)
            {
                throw new IllegalStateException("EC Key Pair Generator not initialised");
            }

            AsymmetricCipherKeyPair     pair = engine.generateKeyPair();
            ECPublicKeyParameters       pub = (ECPublicKeyParameters)pair.getPublic();
            ECPrivateKeyParameters      priv = (ECPrivateKeyParameters)pair.getPrivate();

            if (ecParams == null)
            {
               return new KeyPair(new JCEECPublicKey(algorithm, pub),
                                   new JCEECPrivateKey(algorithm, priv));
            }
            else
            {
                ECParameterSpec p = (ECParameterSpec)ecParams;
                JCEECPublicKey pubKey = new JCEECPublicKey(algorithm, pub, p);
                
                return new KeyPair(pubKey, new JCEECPrivateKey(algorithm, priv, pubKey, p));
            }
        }
    }

    public static class ECDSA
        extends EC
    {
        public ECDSA()
        {
            super("ECDSA");
        }
    }

    public static class ECGOST3410
        extends EC
    {
        public ECGOST3410()
        {
            super("ECGOST3410");
        }
    }

    public static class ECDH
        extends EC
    {
        public ECDH()
        {
            super("ECDH");
        }
    }

    public static class ECDHC
        extends EC
    {
        public ECDHC()
        {
            super("ECDHC");
        }
    }

    public static class ECMQV
        extends EC
    {
        public ECMQV()
        {
            super("ECMQV");
        }
    }
}
