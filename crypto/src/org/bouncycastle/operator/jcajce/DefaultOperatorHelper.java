package org.bouncycastle.operator.jcajce;

import java.security.MessageDigest;
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

    protected MessageDigest createDigest(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        return MessageDigest.getInstance(algorithm);
    }
}