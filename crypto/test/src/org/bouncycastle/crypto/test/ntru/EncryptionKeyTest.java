package org.bouncycastle.crypto.test.ntru;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.NTRUEncryptionKeyPairGenerator;
import org.bouncycastle.crypto.params.NTRUEncryptionParameters;
import org.bouncycastle.crypto.params.NTRUEncryptionPrivateKeyParameters;
import org.bouncycastle.crypto.params.NTRUEncryptionPublicKeyParameters;

public class EncryptionKeyTest
    extends TestCase
{
    public void testEncode()
        throws IOException
    {
        for (NTRUEncryptionParameters params : new NTRUEncryptionParameters[]{NTRUEncryptionParameters.APR2011_743, NTRUEncryptionParameters.APR2011_743_FAST, NTRUEncryptionParameters.EES1499EP1})
        {
            testEncode(params);
        }
    }

    private void testEncode(NTRUEncryptionParameters params)
        throws IOException
    {
        NTRUEncryptionKeyPairGenerator kpGen = new NTRUEncryptionKeyPairGenerator();

        kpGen.init(params);

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        byte[] priv = ((NTRUEncryptionPrivateKeyParameters)kp.getPrivate()).getEncoded();
        byte[] pub = ((NTRUEncryptionPublicKeyParameters)kp.getPublic()).getEncoded();

        AsymmetricCipherKeyPair kp2 = new AsymmetricCipherKeyPair(new NTRUEncryptionPublicKeyParameters(pub, params), new NTRUEncryptionPrivateKeyParameters(priv, params));
        assertEquals(kp.getPublic(), kp2.getPublic());
        assertEquals(kp.getPrivate(), kp2.getPrivate());

        ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
        ByteArrayOutputStream bos2 = new ByteArrayOutputStream();
        ((NTRUEncryptionPrivateKeyParameters)kp.getPrivate()).writeTo(bos1);
        ((NTRUEncryptionPublicKeyParameters)kp.getPublic()).writeTo(bos2);
        ByteArrayInputStream bis1 = new ByteArrayInputStream(bos1.toByteArray());
        ByteArrayInputStream bis2 = new ByteArrayInputStream(bos2.toByteArray());
        AsymmetricCipherKeyPair  kp3 = new AsymmetricCipherKeyPair(new NTRUEncryptionPublicKeyParameters(bis2, params), new NTRUEncryptionPrivateKeyParameters(bis1, params));
        assertEquals(kp.getPublic(), kp3.getPublic());
        assertEquals(kp.getPrivate(), kp3.getPrivate());
    }
}