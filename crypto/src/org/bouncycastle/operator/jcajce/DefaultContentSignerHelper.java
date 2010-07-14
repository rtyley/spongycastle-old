package org.bouncycastle.operator.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

class DefaultContentSignerHelper
    extends ContentSignerHelper
{
    protected Signature createSignature(
        String algorithm)
        throws NoSuchAlgorithmException
    {
        return Signature.getInstance(algorithm);
    }
}