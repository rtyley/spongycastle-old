package org.bouncycastle.operator.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

class DefaultOperatorHelper
    extends OperatorHelper
{
    protected Signature createSignature(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        return Signature.getInstance(algorithm);
    }
}