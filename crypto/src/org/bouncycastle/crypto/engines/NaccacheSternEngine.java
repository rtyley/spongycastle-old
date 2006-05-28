package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;

/**
 * NaccacheStern Engine. For details on this cipher, please see
 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 */
public class NaccacheSternEngine
    implements AsymmetricBlockCipher
{
    private boolean forEncryption;

    private NaccacheSternKeyParameters key;

    private Vector[] lookup = null;

    private boolean debug = false;

    /**
     * Initializes this algorithm. Must be called before all other Functions.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#init(boolean,
     *      org.bouncycastle.crypto.CipherParameters)
     */
    public void init(boolean forEncryption, CipherParameters param)
    {
        this.forEncryption = forEncryption;
        key = (NaccacheSternKeyParameters)param;

        // construct lookup table for faster decryption if necessary
        if (!this.forEncryption)
        {
            if (debug)
            {
                System.out.println("Constructing lookup Array");
            }
            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
            Vector primes = priv.getSmallPrimes();
            lookup = new Vector[primes.size()];
            for (int i = 0; i < primes.size(); i++)
            {
                BigInteger actualPrime = (BigInteger)primes.elementAt(i);
                lookup[i] = new Vector();
                for (int j = 0; j < actualPrime.intValue(); j++)
                {
                    BigInteger comp;
                    comp = (priv.getPhi_n().multiply(BigInteger.valueOf(j))).divide((BigInteger)primes.get(i));
                    lookup[i].add(priv.getG().modPow(comp, priv.getModulus()));
                }
                if (debug)
                {
                    System.out.println("Lookup ArrayList for " + primes.get(i) + " constructed");
                }
            }
        }
    }

    /**
     * Returns the input block size of this algorithm.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#getInputBlockSize()
     * @see org.bouncycastle.crypto.engines.RSAEngine#getInputBlockSize()
     */
    public int getInputBlockSize()
    {
        if (forEncryption)
        {
            // We can only encrypt values up to lowerSigmaBound
            return (key.getLowerSigmaBound() + 7) / 8 - 1;
        }
        else
        {
            // We pad to modulus-size bytes for easier decryption.
            return key.getModulus().toByteArray().length;
        }
    }

    /**
     * Returns the output block size of this algorithm.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#getOutputBlockSize()
     * @see org.bouncycastle.crypto.engines.RSAEngine#getOutputBlockSize()
     */
    public int getOutputBlockSize()
    {
        if (forEncryption)
        {
            // encrypted Data is always padded up to modulus size
            return key.getModulus().toByteArray().length;
        }
        else
        {
            // decrypted Data has upper limit lowerSigmaBound
            return (key.getLowerSigmaBound() + 7) / 8 - 1;
        }
    }

    /**
     * Process a single Block using the Naccache-Stern algorithm.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#processBlock(byte[],
     *      int, int)
     */
    public byte[] processBlock(byte[] in, int inOff, int len) throws InvalidCipherTextException
    {

        if (len > (getInputBlockSize() + 1))
        {
            throw new DataLengthException("input too large for Naccache-Stern cipher.\n");
        }

        if (!forEncryption)
        {
            // At decryption make sure that we receive padded data blocks
            if (len < getInputBlockSize())
            {
                throw new InvalidCipherTextException("BlockLength does not match modulus for Naccache-Stern cipher.\n");
            }
        }

        byte[] block;

        if (inOff != 0 || len != in.length)
        {
            block = new byte[len];
            System.arraycopy(in, inOff, block, 0, len);
        }
        else
        {
            block = in;
        }

        // transform input into BigInteger
        BigInteger input = new BigInteger(1, block);
        if (debug)
        {
            System.out.println("input as BigInteger: " + input);
        }
        byte[] output;
        if (forEncryption)
        {
            // Always return modulus size values 0-padded at the beginning
            // 0-padding at the beginning is correctly parsed by BigInteger :)
            output = key.getModulus().toByteArray();
            Arrays.fill(output, Byte.parseByte("0"));
            byte[] tmp = key.getG().modPow(input, key.getModulus()).toByteArray();
            System.arraycopy(tmp, 0, output, output.length - tmp.length, tmp.length);
            if (debug)
            {
                System.out.println("Encrypted value is:  " + new BigInteger(output));
            }
        }
        else
        {
            Vector plain = new Vector();
            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
            Vector primes = priv.getSmallPrimes();
            // Get Chinese Remainders of CipherText
            for (int i = 0; i < primes.size(); i++)
            {
                BigInteger exp = input.modPow(priv.getPhi_n().divide((BigInteger)primes.get(i)), priv.getModulus());
                Vector al = lookup[i];
                if (lookup[i].size() != ((BigInteger)primes.get(i)).intValue())
                {
                    if (debug)
                    {
                        System.out.println("Prime is " + primes.get(i) + ", lookup table has size " + al.size());
                    }
                    throw new InvalidCipherTextException("Error in lookup Array for "
                                    + ((BigInteger)primes.get(i)).intValue()
                                    + ": Size mismatch. Expected ArrayList with length "
                                    + ((BigInteger)primes.get(i)).intValue() + " but found ArrayList of length "
                                    + lookup[i].size());
                }
                int lookedup = al.indexOf(exp);

                if (lookedup == -1)
                {
                    if (debug)
                    {
                        System.out.println("Actual prime is " + primes.get(i));
                        System.out.println("Decrypted value is " + exp);

                        System.out.println("LookupList for " + primes.get(i) + " with size " + lookup[i].size()
                                        + " is: ");
                        for (int j = 0; j < lookup[i].size(); j++)
                        {
                            System.out.println(lookup[i].get(j));
                        }
                    }
                    throw new InvalidCipherTextException("Lookup failed");
                }
                if (debug)
                {
                    // System.out.println("looking up " + exp + " leads to "
                    // + lookedup);
                }
                plain.add(BigInteger.valueOf(lookedup));
            }
            BigInteger test = chineseRemainder(plain, primes);

            if (debug)
            {
                System.out.println("Probable decryption is " + test);
            }

            // Should not be used as an oracle, so reencrypt output to see
            // if it corresponds to input

            if ((key.getG().modPow(test, key.getModulus())).equals(input))
            {
                output = test.toByteArray();
            }
            else
            {
                output = null;
            }

        }

        return output;
    }

    /**
     * Convenience Method for data exchange with the cipher.
     * 
     * Determines blocksize and splits data to blocksize.
     *
     * @param data the data to be processed
     * @return the data after it went through the NaccacheSternEngine.
     * @throws InvalidCipherTextException 
     */
    public byte[] processData(byte[] data) throws InvalidCipherTextException
    {
        if (debug)
        {
            System.out.println();
        }
        if (data.length > getInputBlockSize())
        {
            int inBlocksize = getInputBlockSize();
            int outBlocksize = getOutputBlockSize();
            if (debug)
            {
                System.out.println("Input blocksize is:  " + inBlocksize + " bytes");
                System.out.println("Output blocksize is: " + outBlocksize + " bytes");
                System.out.println("Data has length:.... " + data.length + " bytes");
            }
            int datapos = 0;
            int retpos = 0;
            byte[] retval = new byte[(data.length / inBlocksize + 1) * outBlocksize];
            while (datapos < data.length)
            {
                byte[] tmp;
                if (datapos + inBlocksize < data.length)
                {
                    tmp = processBlock(data, datapos, inBlocksize);
                    datapos += inBlocksize;
                }
                else
                {
                    tmp = processBlock(data, datapos, data.length - datapos);
                    datapos += data.length - datapos;
                }
                if (debug)
                {
                    System.out.println("new datapos is " + datapos);
                }
                if (tmp != null)
                {
                    for (int i = 0; i < tmp.length; i++)
                    {
                        retval[i + retpos] = tmp[i];
                    }
                    retpos += tmp.length;
                }
                else
                {
                    if (debug)
                    {
                        System.out.println("cipher returned null");
                    }
                    throw new InvalidCipherTextException("cipher returned null");
                }
            }
            byte[] ret = new byte[retpos];
            for (int i = 0; i < retpos; i++)
            {
                ret[i] = retval[i];
            }
            if (debug)
            {
                System.out.println("returning " + ret.length + " bytes");
            }
            return ret;
        }
        else
        {
            if (debug)
            {
                System.out.println("data size is less then input block size, processing directly");
            }
            return processBlock(data, 0, data.length);
        }
    }

    /**
     * Computes the integer x that is expressed through the given primes and the
     * congruences with the chinese remainder theorem (CRT).
     * 
     * @param congruences
     *            the congruences c_i
     * @param primes
     *            the primes p_i
     * @return an integer x for that x % p_i == c_i
     */
    private static BigInteger chineseRemainder(Vector congruences, Vector primes)
    {
        BigInteger retval = BigInteger.ZERO;
        BigInteger all = BigInteger.ONE;
        for (int i = 0; i < primes.size(); i++)
        {
            all = all.multiply((BigInteger)primes.elementAt(i));
        }
        for (int i = 0; i < primes.size(); i++)
        {
            BigInteger a = (BigInteger)primes.elementAt(i);
            BigInteger b = all.divide(a);
            BigInteger b_ = b.modInverse(a);
            BigInteger tmp = b.multiply(b_);
            tmp = tmp.multiply((BigInteger)congruences.elementAt(i));
            retval = retval.add(tmp);
        }

        return retval.mod(all);
    }
}
