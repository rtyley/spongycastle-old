package org.bouncycastle.cms;

import java.security.SecureRandom;
import java.security.Provider;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.io.OutputStream;
import java.io.IOException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class CMSAuthenticatedGenerator
    extends CMSEnvelopedGenerator
{
    /**
     * base constructor
     */
    public CMSAuthenticatedGenerator()
    {
    }

    /**
     * constructor allowing specific source of randomness
     *
     * @param rand instance of SecureRandom to use
     */
    public CMSAuthenticatedGenerator(
        SecureRandom rand)
    {
        super(rand);
    }

    protected AlgorithmIdentifier getAlgorithmIdentifier(String encryptionOID, AlgorithmParameterSpec paramSpec, Provider provider)
        throws IOException, NoSuchAlgorithmException, InvalidParameterSpecException
    {
        AlgorithmParameters params = CMSEnvelopedHelper.INSTANCE.createAlgorithmParameters(encryptionOID, provider);
        params.init(paramSpec);

        return getAlgorithmIdentifier(encryptionOID, params);
    }

    protected AlgorithmParameterSpec generateParameterSpec(String encryptionOID, SecretKey encKey, Provider encProvider)
        throws CMSException
    {
        try
        {
            if (encryptionOID.equals(RC2_CBC))
            {
                byte[] iv = new byte[8];

                rand.nextBytes(iv);

                return new RC2ParameterSpec(encKey.getEncoded().length * 8, iv);
            }

            AlgorithmParameterGenerator pGen = CMSEnvelopedHelper.INSTANCE.createAlgorithmParameterGenerator(encryptionOID, encProvider);

            AlgorithmParameters p = pGen.generateParameters();

            return p.getParameterSpec(IvParameterSpec.class);
        }
        catch (GeneralSecurityException e)
        {
            return null;
        }
    }

    protected static class MacOutputStream
        extends OutputStream
    {
        private final OutputStream out;
        private Mac mac;

        MacOutputStream(OutputStream out, Mac mac)
        {
            this.out = out;
            this.mac = mac;
        }

        public void write(byte[] buf)
            throws IOException
        {
            mac.update(buf, 0, buf.length);
            out.write(buf, 0, buf.length);
        }

        public void write(byte[] buf, int off, int len)
            throws IOException
        {
            mac.update(buf, off, len);
            out.write(buf, off, len);
        }

        public void write(int i)
            throws IOException
        {
            mac.update((byte)i);
            out.write(i);
        }

        public void close()
            throws IOException
        {
            out.close();
        }
        
        public byte[] getMac()
        {
            return mac.doFinal();
        }
    }
}
