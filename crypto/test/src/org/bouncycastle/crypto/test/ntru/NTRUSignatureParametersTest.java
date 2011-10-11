package org.bouncycastle.crypto.test.ntru;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.NTRUSigningParameters;

public class NTRUSignatureParametersTest
    extends TestCase
{
    public void testLoadSave()
        throws IOException
    {
        for (NTRUSigningParameters params : new NTRUSigningParameters[]{NTRUSigningParameters.TEST157, NTRUSigningParameters.TEST157_PROD})
        {
            testLoadSave(params);
        }
    }

    private void testLoadSave(NTRUSigningParameters params)
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        assertEquals(params, new NTRUSigningParameters(is));
    }

    public void testEqualsHashCode()
        throws IOException
    {
        for (NTRUSigningParameters params : new NTRUSigningParameters[]{NTRUSigningParameters.TEST157, NTRUSigningParameters.TEST157_PROD})
        {
            testEqualsHashCode(params);
        }
    }

    private void testEqualsHashCode(NTRUSigningParameters params)
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        params.writeTo(os);
        ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
        NTRUSigningParameters params2 = new NTRUSigningParameters(is);

        assertEquals(params, params2);
        assertEquals(params.hashCode(), params2.hashCode());

        params.N += 1;
        assertFalse(params.equals(params2));
        assertFalse(params.equals(params2));
        assertFalse(params.hashCode() == params2.hashCode());
    }

    public void testClone()
    {
        for (NTRUSigningParameters params : new NTRUSigningParameters[]{NTRUSigningParameters.TEST157, NTRUSigningParameters.TEST157_PROD})
        {
            assertEquals(params, params.clone());
        }
    }
}