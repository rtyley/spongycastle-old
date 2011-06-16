package org.bouncycastle.openpgp.operator.jcajce;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

public class JcaPGPKeyConverter
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    public JcaPGPKeyConverter setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcaPGPKeyConverter setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public PublicKey getPublicKey(PGPPublicKey publicKey)
        throws PGPException
    {
        KeyFactory fact;

        PublicKeyPacket publicPk = publicKey.getPublicKeyPacket();

        try
        {
            switch (publicPk.getAlgorithm())
            {
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
                RSAPublicBCPGKey rsaK = (RSAPublicBCPGKey)publicPk.getKey();
                RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsaK.getModulus(), rsaK.getPublicExponent());

                fact = helper.createKeyFactory("RSA");

                return fact.generatePublic(rsaSpec);
            case PublicKeyAlgorithmTags.DSA:
                DSAPublicBCPGKey dsaK = (DSAPublicBCPGKey)publicPk.getKey();
                DSAPublicKeySpec dsaSpec = new DSAPublicKeySpec(dsaK.getY(), dsaK.getP(), dsaK.getQ(), dsaK.getG());

                fact = helper.createKeyFactory("DSA");

                return fact.generatePublic(dsaSpec);
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                ElGamalPublicBCPGKey elK = (ElGamalPublicBCPGKey)publicPk.getKey();
                ElGamalPublicKeySpec elSpec = new ElGamalPublicKeySpec(elK.getY(), new ElGamalParameterSpec(elK.getP(), elK.getG()));

                fact = helper.createKeyFactory("ElGamal");

                return fact.generatePublic(elSpec);
            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("exception constructing public key", e);
        }
    }

    public PrivateKey getPrivateKey(PGPPrivateKey privKey)
        throws PGPException
    {
        PublicKeyPacket pubPk = privKey.getPublicKeyPacket();
        BCPGKey privPk = privKey.getPrivateKeyDataPacket();

        try
        {
            KeyFactory         fact;

            switch (pubPk.getAlgorithm())
            {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
            case PGPPublicKey.RSA_SIGN:
                RSAPublicBCPGKey        rsaPub = (RSAPublicBCPGKey)pubPk.getKey();
                RSASecretBCPGKey rsaPriv = (RSASecretBCPGKey)privPk;
                RSAPrivateCrtKeySpec rsaPrivSpec = new RSAPrivateCrtKeySpec(
                                                    rsaPriv.getModulus(),
                                                    rsaPub.getPublicExponent(),
                                                    rsaPriv.getPrivateExponent(),
                                                    rsaPriv.getPrimeP(),
                                                    rsaPriv.getPrimeQ(),
                                                    rsaPriv.getPrimeExponentP(),
                                                    rsaPriv.getPrimeExponentQ(),
                                                    rsaPriv.getCrtCoefficient());

                fact = helper.createKeyFactory("RSA");

                return fact.generatePrivate(rsaPrivSpec);
            case PGPPublicKey.DSA:
                DSAPublicBCPGKey    dsaPub = (DSAPublicBCPGKey)pubPk.getKey();
                DSASecretBCPGKey dsaPriv = (DSASecretBCPGKey)privPk;
                DSAPrivateKeySpec dsaPrivSpec =
                                            new DSAPrivateKeySpec(dsaPriv.getX(), dsaPub.getP(), dsaPub.getQ(), dsaPub.getG());

                fact = helper.createKeyFactory("DSA");

                return fact.generatePrivate(dsaPrivSpec);
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                ElGamalPublicBCPGKey    elPub = (ElGamalPublicBCPGKey)pubPk.getKey();
                ElGamalSecretBCPGKey elPriv = (ElGamalSecretBCPGKey)privPk;
                ElGamalPrivateKeySpec elSpec = new ElGamalPrivateKeySpec(elPriv.getX(), new ElGamalParameterSpec(elPub.getP(), elPub.getG()));

                fact = helper.createKeyFactory("ElGamal");

                return fact.generatePrivate(elSpec);
            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception constructing key", e);
        }
    }
}
