package org.bouncycastle.crypto.test.ntru;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.NTRUSignatureParameters;

public class NTRUSignatureParametersTest
    extends TestCase
{
    public void testLoadSave()
        throws IOException
    {
        for (NTRUSignatureParameters params : new NTRUSignatureParameters[]{NTRUSignatureParameters.TEST157, NTRUSignatureParameters.TEST157_PROD})
        {
            testLoadSave(params);
        }
    }

    private void testLoadSave(NTRUSignatureParameters params)
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        assertEquals(params, new NTRUSignatureParameters(is));
    }

    public void testEqualsHashCode()
        throws IOException
    {
        for (NTRUSignatureParameters params : new NTRUSignatureParameters[]{NTRUSignatureParameters.TEST157, NTRUSignatureParameters.TEST157_PROD})
        {
            testEqualsHashCode(params);
        }
    }

    private void testEqualsHashCode(NTRUSignatureParameters params)
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        NTRUSignatureParameters params2 = new NTRUSignatureParameters(is);

        assertEquals(params, params2);
        assertEquals(params.hashCode(), params2.hashCode());

        params.N += 1;
        assertFalse(params.equals(params2));
        assertFalse(params.equals(params2));
        assertFalse(params.hashCode() == params2.hashCode());
    }

    public void testClone()
    {
        for (NTRUSignatureParameters params : new NTRUSignatureParameters[]{NTRUSignatureParameters.TEST157, NTRUSignatureParameters.TEST157_PROD})
        {
            assertEquals(params, params.clone());
        }
    }
}