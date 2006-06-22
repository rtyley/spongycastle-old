package org.bouncycastle.crypto.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;

/**
 * Used for (de)serializing NaccacheSternKeyParameters.
 * 
 * @author lippold
 * 
 */
public class NaccacheSternKeySerializationFactory
{
    private static final long serialVersionUID = -4600756363887771173L;

    private final static int PUBLIC_KEY = 1;

    private final static int PRIVATE_KEY = 2;

    public static byte[] getSerialized(NaccacheSternKeyParameters key)
            throws IOException
    {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeLong(serialVersionUID);
        if (key instanceof NaccacheSternPrivateKeyParameters)
        {
            oos.write(PRIVATE_KEY);
        }
        else
        {
            oos.write(PUBLIC_KEY);
        }

        oos.writeObject(key.getG());
        oos.writeObject(key.getModulus());
        oos.writeObject(key.getSigma());

        if (key instanceof NaccacheSternPrivateKeyParameters)
        {
            final NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters) key;
            oos.writeObject(priv.getSmallPrimes());
            oos.writeObject(priv.getPhi_n());
            oos.writeObject(priv.getLookupTable());
        }

        oos.close();
        baos.flush();
        final byte[] retval = baos.toByteArray();
        baos.close();
        return retval;
    }

    public static NaccacheSternKeyParameters deserialize(
            byte[] naccacheSternKeyParameters) throws IOException,
            ClassNotFoundException
    {
        final ByteArrayInputStream bais = new ByteArrayInputStream(
                naccacheSternKeyParameters);
        final ObjectInputStream ois = new ObjectInputStream(bais);
        final long serializedData = ois.readLong();
        if (serializedData != serialVersionUID)
        {
            throw new IllegalArgumentException(
                    "The supplied byte[] was not serialized by "
                            + NaccacheSternKeySerializationFactory.class
                                    .getName());
        }
        final int type = ois.read();
        final BigInteger g = (BigInteger) ois.readObject();
        final BigInteger n = (BigInteger) ois.readObject();
        final BigInteger sigma = (BigInteger) ois.readObject();
        if (type == PRIVATE_KEY)
        {
            final Vector smallPrimes = (Vector) ois.readObject();
            final BigInteger phi_n = (BigInteger) ois.readObject();
            final Hashtable lookup = (Hashtable) ois.readObject();
            ois.close();
            bais.close();
            return new NaccacheSternPrivateKeyParameters(g, n, sigma, smallPrimes, phi_n, lookup);
        }
        else
        {
            ois.close();
            bais.close();
            return new NaccacheSternKeyParameters(g, n, sigma);
        }
    }

}
