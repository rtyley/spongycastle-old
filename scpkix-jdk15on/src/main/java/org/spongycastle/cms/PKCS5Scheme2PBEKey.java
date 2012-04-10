package org.spongycastle.cms;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;

import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;

/**
 * PKCS5 scheme-2 - password converted to bytes assuming ASCII.
 */
public class PKCS5Scheme2PBEKey
    extends CMSPBEKey
{
    public PKCS5Scheme2PBEKey(char[] password, byte[] salt, int iterationCount)
    {
        super(password, salt, iterationCount);
    }

    public PKCS5Scheme2PBEKey(char[] password, AlgorithmParameters pbeParams)
        throws InvalidAlgorithmParameterException
    {
        super(password, getParamSpec(pbeParams));
    }

    byte[] getEncoded(String algorithmOid)
    {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator();

        gen.init(PBEParametersGenerator.PKCS5PasswordToBytes(this.getPassword()), this.getSalt(), this.getIterationCount());

        return ((KeyParameter)gen.generateDerivedParameters(CMSEnvelopedHelper.INSTANCE.getKeySize(algorithmOid))).getKey();
    }
}
