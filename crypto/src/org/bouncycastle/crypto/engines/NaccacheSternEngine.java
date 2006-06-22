package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Hashtable;
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
public class NaccacheSternEngine implements AsymmetricBlockCipher
{
    private boolean forEncryption;

    private NaccacheSternKeyParameters key;

    private Hashtable lookup;

    private boolean debug = false;

    private Vector threads;

    private Object waitFor = new Object();

    private Vector plain;

    private BigInteger certificate;

    private final int processorCount;

    public NaccacheSternEngine()
    {
        processorCount = 1;
    }

    public NaccacheSternEngine(int processorCnt)
    {
        processorCount = processorCnt;
    }

    /**
     * Initializes this algorithm. Must be called before all other Functions.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#init(boolean,
     *      org.bouncycastle.crypto.CipherParameters)
     */
    public void init(final boolean forEncryption, final CipherParameters param)
    {
        this.forEncryption = forEncryption;

        // construct lookup table for faster decryption if necessary
        if (this.forEncryption)
        {
            key = (NaccacheSternKeyParameters) param;
        }
        else
        {
            final NaccacheSternPrivateKeyParameters privKey = (NaccacheSternPrivateKeyParameters) param;
            lookup = privKey.getLookupTable();
            key = privKey;
        }
    }

    public void setDebug(final boolean debug)
    {
        this.debug = debug;
    }

    /**
     * Returns the input block size of this algorithm.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#getInputBlockSize()
     */
    public int getInputBlockSize()
    {
        if (forEncryption)
        {
            // We can only encrypt values up to lowerSigmaBound
            return (key.getSigma().bitLength() + 7) / 8 - 1;
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
            return (key.getSigma().bitLength() + 7 / 8) + 1;
        }
    }

    /**
     * Process a single Block using the Naccache-Stern algorithm.
     * 
     * @see org.bouncycastle.crypto.AsymmetricBlockCipher#processBlock(byte[],
     *      int, int)
     */
    public byte[] processBlock(final byte[] input, final int inOff,
            final int len) throws InvalidCipherTextException
    {

        if (!forEncryption && len < getInputBlockSize())
        {
            // At decryption make sure that we receive padded data blocks
            throw new InvalidCipherTextException(
                    "BlockLength does not match modulus for Naccache-Stern cipher.\n");
        }

        byte[] block;

        if (inOff != 0 || len != input.length)
        {
            block = new byte[len];
            System.arraycopy(input, inOff, block, 0, len);
        }
        else
        {
            block = input;
        }

        // transform input into BigInteger
        final BigInteger input_converted = new BigInteger(1, block);

        if (forEncryption && input_converted.compareTo(key.getSigma()) > 0)
        {
            throw new DataLengthException(
                    "input too large for Naccache-Stern cipher.\n");
        }
        if (debug)
        {
            System.out.println("input as BigInteger: " + input_converted);
        }
        byte[] output;
        if (forEncryption)
        {
            output = encrypt(input_converted);
        }
        else
        {
            output = decrypt(input_converted);
        }

        return output;
    }

    private synchronized byte[] decrypt(final BigInteger input)
    {
        final NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters) key;
        final Vector primes = priv.getSmallPrimes();
        plain = new Vector(primes.size());
        threads = new Vector();
        // Get Chinese Remainders of CipherText
        for (int i = 0; i < primes.size(); i++)
        {
            // insert objects into plain, so I can use Vector.setElementAt()
            plain.add(new Object());
            final BigInteger smallPrime = (BigInteger) primes.get(i);
            final Thread t = new DecryptBySmallPrime(smallPrime, input, priv
                    .getPhi_n(), priv.getModulus(), debug);
            threads.add(t);
        }

        final Vector runningThreads = new Vector();

        synchronized (threads)
        {
            for (int i = 0; i < threads.size() && i < processorCount; i++)
            {
                final Thread t = (Thread) threads.get(i);
                runningThreads.add(t);
                t.start();
            }
        }
        synchronized (waitFor)
        {
            while (threads.size() > 0)
            {
                try
                {
                    waitFor.wait();
                }
                catch (InterruptedException e)
                {
                }
                for (int i = 0; i < threads.size(); i++)
                {
                    final Thread t = (Thread) threads.get(i);
                    if (!runningThreads.contains(t))
                    {
                        runningThreads.add(t);
                        t.start();
                        break;
                    }
                }
            }
        }
        for (int i = 0; i < runningThreads.size(); i++)
        {
            final Thread t = (Thread) runningThreads.get(i);
            try
            {
                t.join();
            }
            catch (InterruptedException e)
            {
            }
        }

        final BigInteger test = chineseRemainder(plain, primes);

        // Should not be used as an oracle, so reencrypt output to see
        // if it corresponds to input

        // this breaks probabilisic encryption, so disable it. Anyway, we do
        // use the first n primes for key generation, so it is pretty easy
        // to guess them. But as stated in the paper, this is not a security
        // breach. So we can just work with the correct sigma.

        // if (debug) {
        // System.out.println("Decryption is " + test);
        // }
        // if ((key.getG().modPow(test, key.getModulus())).equals(input)) {
        // output = test.toByteArray();
        // } else {
        // if(debug){
        // System.out.println("Engine seems to be used as an oracle,
        // returning null");
        // }
        // output = null;
        // }

        return test.toByteArray();

    }

    /**
     * Encrypts a BigInteger aka Plaintext with the public key. Uses
     * probabilistic encryption if a certificate is set.
     * 
     * @param plain
     *            The BigInteger to encrypt
     * @return The byte[] representation of the encrypted BigInteger (i.e.
     *         crypted.toByteArray())
     */
    public byte[] encrypt(final BigInteger plain)
    {
        // Always return modulus size values 0-padded at the beginning
        // 0-padding at the beginning is correctly parsed by BigInteger :)
        final byte[] output = key.getModulus().toByteArray();
        Arrays.fill(output, Byte.parseByte("0"));
        BigInteger encrypted = key.getG().modPow(plain, key.getModulus());
        if (certificate != null)
        {
            encrypted = certificate.modPow(key.getSigma(), key.getModulus())
                    .multiply(encrypted).mod(key.getModulus());
        }

        final byte[] tmp = encrypted.toByteArray();
        System
                .arraycopy(tmp, 0, output, output.length - tmp.length,
                        tmp.length);
        if (debug)
        {
            System.out
                    .println("Encrypted value is:  " + new BigInteger(output));
        }
        return output;
    }

    /**
     * Adds the contents of two encrypted blocks mod sigma
     * 
     * @param block1
     *            the first encrypted block
     * @param block2
     *            the second encrypted block
     * @return an encrypted block, so that decrypt(retval) = ( decrypt(block1) +
     *         decrypt(block2) ) % sigma
     * @throws InvalidCipherTextException
     */
    public byte[] addCryptedBlocks(final byte[] block1, final byte[] block2)
            throws InvalidCipherTextException
    {
        final BigInteger m1Crypt = new BigInteger(1, block1);
        final BigInteger m2Crypt = new BigInteger(1, block2);

        // check for correct blocksize
        if (m1Crypt.compareTo(key.getModulus()) >= 0
                || m2Crypt.compareTo(key.getModulus()) >= 0)
        {
            throw new InvalidCipherTextException(
                    "BlockLength too large for addition");
        }

        // calculate resulting block
        BigInteger m1m2Crypt = m1Crypt.multiply(m2Crypt);
        m1m2Crypt = m1m2Crypt.mod(key.getModulus());
        if (debug)
        {
            System.out.println("c(m1) as BigInteger:......... " + m1Crypt);
            System.out.println("c(m2) as BigInteger:......... " + m2Crypt);
            System.out.println("(c(m1)*c(m2))%n = c(m1+m2)%n: " + m1m2Crypt);
        }

        final byte[] output = key.getModulus().toByteArray();
        Arrays.fill(output, Byte.parseByte("0"));
        System.arraycopy(m1m2Crypt.toByteArray(), 0, output, output.length
                - m1m2Crypt.toByteArray().length,
                m1m2Crypt.toByteArray().length);

        return output;
    }

    /**
     * Multiplies block1 by value (mod sigma).
     * 
     * @param block1
     *            The encrypted block to be multiplied.
     * @param value
     *            The value by which it shall be multiplied
     * @return an encrypted block, so that decrypt(retval) = ( decrypt(block1) *
     *         value ) % sigma
     * @throws InvalidCipherTextException
     */
    public byte[] multiplyCryptedBlock(final byte[] block1,
            final BigInteger value) throws InvalidCipherTextException
    {

        final BigInteger m1Crypt = new BigInteger(1, block1);
        if (m1Crypt.compareTo(key.getModulus()) >= 0)
        {
            throw new InvalidCipherTextException(
                    "BlockLength too large for multiplication.\n");
        }

        // calculate resulting block
        final BigInteger m1m2Crypt = m1Crypt.modPow(value, key.getModulus());
        if (debug)
        {
            System.out.println("c(m1) as BigInteger:....... " + m1Crypt);
            System.out.println("m2 as BigInteger:.......... " + value);
            System.out.println("(c(m1)^m2)%n = c(m1*m2)%n: " + m1m2Crypt);
        }

        final byte[] output = key.getModulus().toByteArray();
        Arrays.fill(output, Byte.parseByte("0"));
        System.arraycopy(m1m2Crypt.toByteArray(), 0, output, output.length
                - m1m2Crypt.toByteArray().length,
                m1m2Crypt.toByteArray().length);

        return output;
    }

    /**
     * Convenience Method for data exchange with the cipher.
     * 
     * Determines blocksize and splits data to blocksize.
     * 
     * @param data
     *            the data to be processed
     * @return the data after it went through the NaccacheSternEngine.
     * @throws InvalidCipherTextException
     */
    public byte[] processData(final byte[] data)
            throws InvalidCipherTextException
    {
        if (debug)
        {
            System.out.println();
        }
        final BigInteger dataConverted = new BigInteger(1, data);
        if (dataConverted.compareTo(key.getSigma()) > 0)
        {
            final int inBlocksize = getInputBlockSize();
            final int outBlocksize = getOutputBlockSize();
            if (debug)
            {
                System.out.println("Input blocksize is:  " + inBlocksize
                        + " bytes");
                System.out.println("Output blocksize is: " + outBlocksize
                        + " bytes");
                System.out.println("Data has length:.... " + data.length
                        + " bytes");
            }
            int datapos = 0;
            int retpos = 0;
            byte[] retval = new byte[(data.length / inBlocksize + 1)
                    * outBlocksize];
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
            System.arraycopy(retval, 0, ret, 0, retpos);
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
                System.out
                        .println("data size is less then input block size, processing directly");
            }
            return processBlock(data, 0, data.length);
        }
    }

    /**
     * Set the certificate for this engine. This is a BigInteger that is used by
     * probabilistic encryption to conceal the actual encrypted value. This also
     * allows for changing certificates before an encryption process. The
     * certificate remains valid for this enigne until a new one is set.
     * 
     * @param certificate
     *            The BigInteger used as a certificate to conceal the encrypted
     *            value.
     */
    public void setCertificate(BigInteger certificate)
    {
        this.certificate = certificate;
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
    private static BigInteger chineseRemainder(final Vector congruences,
            final Vector primes)
    {
        BigInteger retval = BigInteger.ZERO;
        BigInteger all = BigInteger.ONE;
        for (int i = 0; i < primes.size(); i++)
        {
            all = all.multiply((BigInteger) primes.elementAt(i));
        }
        for (int i = 0; i < primes.size(); i++)
        {
            final BigInteger a = (BigInteger) primes.elementAt(i);
            final BigInteger b = all.divide(a);
            final BigInteger b_ = b.modInverse(a);
            BigInteger tmp = b.multiply(b_);
            tmp = tmp.multiply((BigInteger) congruences.elementAt(i));
            retval = retval.add(tmp);
        }

        return retval.mod(all);
    }

    private void submitDecryptionValue(final DecryptBySmallPrime t)
    {
        if (t.lookedup == -1)
        {
            if (debug)
            {
                System.out.println("Actual prime is " + t.smallPrime);
                System.out.println("Decrypted value is " + t.exp);

                System.out.println("LookupList for " + t.smallPrime
                        + " with size " + t.al.size() + " is: ");
                for (int j = 0; j < t.al.size(); j++)
                {
                    System.out.println(t.al.get(j));
                }
            }
            return;
        }

        final NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters) key;
        final Vector smallPrimes = priv.getSmallPrimes();
        plain.setElementAt(BigInteger.valueOf(t.lookedup), smallPrimes
                .indexOf(t.smallPrime));
        synchronized (threads)
        {
            threads.remove(t);
        }

        synchronized (waitFor)
        {
            waitFor.notifyAll();
        }
    }

    class DecryptBySmallPrime extends Thread
    {
        private final BigInteger smallPrime;

        private final BigInteger input;

        private final BigInteger phi_n;

        private final BigInteger modulus;

        private BigInteger exp;

        private int lookedup;

        private Vector al;

        private boolean debug;

        DecryptBySmallPrime(BigInteger smallPrime, BigInteger input,
                BigInteger phi_n, BigInteger modulus, boolean debug)
        {
            super();
            this.smallPrime = smallPrime;
            this.input = input;
            this.phi_n = phi_n;
            this.modulus = modulus;
            this.debug = debug;
        }

        public void run()
        {
            exp = input.modPow(phi_n.divide(smallPrime), modulus);
            al = (Vector) lookup.get(smallPrime);
            lookedup = al.indexOf(exp);
            if (debug)
            {
                System.out.println("decryption for prime " + smallPrime
                        + " finished.");
            }
            submitDecryptionValue(this);
        }
    }

}
