package org.bouncycastle.crypto.test.ntru;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.NTRUEncryptionParameters;

public class NTRUEncryptionParametersTest
    extends TestCase
{
    public void testLoadSave()
        throws IOException
    {
        NTRUEncryptionParameters params = NTRUEncryptionParameters.EES1499EP1;
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        assertEquals(params, new NTRUEncryptionParameters(is));
    }

    public void testEqualsHashCode()
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        NTRUEncryptionParameters.EES1499EP1.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        NTRUEncryptionParameters params = new NTRUEncryptionParameters(is);

        assertEquals(params, NTRUEncryptionParameters.EES1499EP1);
        assertEquals(params.hashCode(), NTRUEncryptionParameters.EES1499EP1.hashCode());

        params.N += 1;
        assertFalse(params.equals(NTRUEncryptionParameters.EES1499EP1));
        assertFalse(NTRUEncryptionParameters.EES1499EP1.equals(params));
        assertFalse(params.hashCode() == NTRUEncryptionParameters.EES1499EP1.hashCode());
    }

    public void testClone()
    {
        NTRUEncryptionParameters params = NTRUEncryptionParameters.APR2011_439;
        assertEquals(params, params.clone());

        params = NTRUEncryptionParameters.APR2011_439_FAST;
        assertEquals(params, params.clone());
    }
}