package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;

/**
 * Key generation parameters for NaccacheStern cipher. For details on this
 * cipher, please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 */
public class NaccacheSternKeyPairGenerator 
     implements AsymmetricCipherKeyPairGenerator
{

    private NaccacheSternKeyGenerationParameters param;

    private final Vector threads = new Vector();

    private final Object waitFor = new Object();

    private final Hashtable gParts = new Hashtable();

    //private static final int PROCESSOR_CNT = Runtime.getRuntime().availableProcessors();

    private static final int PROCESSOR_CNT = 1;
    
    private boolean gDivisible = false;

    private BigInteger a = null;

    private BigInteger b = null;

    private BigInteger u;

    private BigInteger v;

    private BigInteger p = null;

    private BigInteger q = null;

    private BigInteger p_ = null;

    private BigInteger q_ = null;

    private BigInteger g;

    private BigInteger n;

    private BigInteger sigma;

    private BigInteger phi_n;

    private boolean debug;

    private int strength;

    private SecureRandom rand;

    private int certainty;

    private Vector smallPrimes;

    /*
     * (non-Javadoc)
     * 
     * @see org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator#init(org.bouncycastle.crypto.KeyGenerationParameters)
     */
    public void init(final KeyGenerationParameters param)
    {
        this.param = (NaccacheSternKeyGenerationParameters) param;
        strength = param.getStrength();
        rand = param.getRandom();
        certainty = this.param.getCertainty();
        debug = this.param.isDebug();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator#generateKeyPair()
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        if (debug)
        {
            System.out.println("Fetching first " + param.getCntSmallPrimes()
                    + " primes.");
        }

        smallPrimes = findFirstPrimes(param.getCntSmallPrimes());
        smallPrimes = permuteList(smallPrimes, rand);

        u = BigInteger.ONE;
        v = BigInteger.ONE;

        for (int i = 0; i < smallPrimes.size() / 2; i++)
        {
            u = u.multiply((BigInteger) smallPrimes.get(i));
        }
        for (int i = smallPrimes.size() / 2; i < smallPrimes.size(); i++)
        {
            v = v.multiply((BigInteger) smallPrimes.get(i));
        }

        sigma = u.multiply(v);

        generateAB();

        if (debug)
        {
            System.out.println("generating p and q");
        }

        generatePQ();

        n = p.multiply(q);
        phi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        if (debug)
        {
            System.out.println("generating g");
        }
        
        computeG();
        
        if (debug)
        {
            System.out.println();
            System.out.println("found new NaccacheStern cipher variables:");
            System.out.println("smallPrimes: " + smallPrimes);
            System.out.println("sigma:...... " + sigma + " ("
                    + sigma.bitLength() + " bits)");
            System.out.println("a:.......... " + a);
            System.out.println("b:.......... " + b);
            System.out.println("p':......... " + p_);
            System.out.println("q':......... " + q_);
            System.out.println("p:.......... " + p);
            System.out.println("q:.......... " + q);
            System.out.println("n:.......... " + n);
            System.out.println("phi(n):..... " + phi_n);
            System.out.println("g:.......... " + g);
            System.out.println();
        }

        return new AsymmetricCipherKeyPair(new NaccacheSternKeyParameters(
                false, g, n, sigma.bitLength()),
                new NaccacheSternPrivateKeyParameters(g, n, sigma.bitLength(),
                        smallPrimes, phi_n, debug));
    }

    private static BigInteger computeP(final BigInteger a, final BigInteger u,
            final BigInteger p_)
    {
        return (((p_.multiply(BigInteger.valueOf(2))).multiply(a)).multiply(u))
                .add(BigInteger.ONE);
    }

    private static BigInteger generatePrime(final int bitLength,
            final int certainty, final SecureRandom rand)
    {
        BigInteger p_ = new BigInteger(bitLength, certainty, rand);
        while (p_.bitLength() != bitLength)
        {
            p_ = new BigInteger(bitLength, certainty, rand);
        }
        return p_;
    }

    private void submitGPart(final ComputeGPart t)
    {
        synchronized (gParts)
        {
            gParts.put(t.smallPrime, t.gPart);
        }

        synchronized (threads)
        {
            threads.remove(t);
        }

        synchronized (waitFor)
        {
            waitFor.notify();
        }
    }

    private void submitDivisionTest(boolean result, Thread t)
    {
        if (result)
        {
            gDivisible = result;
            synchronized (threads)
            {
                threads.removeAllElements();
            }
        }
        synchronized (threads)
        {
            threads.remove(t);
        }
        synchronized (waitFor)
        {
            waitFor.notifyAll();
        }
    }

    private void submitPQ(final BigInteger p, final BigInteger q,
            final BigInteger p_, final BigInteger q_)
    {
        this.p = p;
        this.q = q;
        this.p_ = p_;
        this.q_ = q_;

        synchronized (waitFor)
        {
            waitFor.notifyAll();
        }
    }

    /**
     * Generates a permuted ArrayList from the original one. The original List
     * is not modified
     * 
     * @param arr
     *            the ArrayList to be permuted
     * @param rand
     *            the source of Randomness for permutation
     * @return a new ArrayList with the permuted elements.
     */
    private static Vector permuteList(final Vector arr, final SecureRandom rand)
    {
        final Vector retval = new Vector();
        final Vector tmp = new Vector();
        for (int i = 0; i < arr.size(); i++)
        {
            tmp.add(arr.get(i));
        }
        retval.add(tmp.remove(0));
        while (tmp.size() != 0)
        {
            retval.add(rand.nextInt(retval.size() + 1), tmp.remove(0));
        }
        return retval;
    }

    /**
     * Gets the first n primes with a sieve of Erathostenes.
     * 
     * @param count
     *            the number of primes to find
     * @return a integer array containing the first count primes starting with 2
     */
    public static int[] getFirstPrimes(final int count)
    {
        int pos = 0;
        long testRange = 4;
        int sqrPos = 0;
        int[] retval = new int[count];
        retval[0] = 2;
        int current = 3;
        boolean isPrime = true;
        while (pos < count - 1)
        {
            if (testRange <= current)
            {
                sqrPos++;
                testRange = retval[sqrPos] * retval[sqrPos];
            }
            isPrime = true;
            for (int i = 0; i < sqrPos; i++)
            {
                if (current % retval[i] == 0)
                {
                    isPrime = false;
                    break;
                }
            }
            if (isPrime)
            {
                pos++;
                retval[pos] = current;
            }
            current++;
        }
        return retval;
    }

    private void generateAB()
    {

        // n = (2 a u p_ + 1 ) ( 2 b v q_ + 1)
        // -> |n| = strength
        // |2| = 1 in bits
        // -> |a| * |b| = |n| - |u| - |v| - |p_| - |q_| - |2| -|2|
        // remainingStrength = strength - sigma.bitLength() - p_.bitLength() -
        // q_.bitLength() - 1 -1
        final int remainingStrength = (strength - sigma.bitLength() - 48) / 2 + 1;

        if (PROCESSOR_CNT == 1)
        {
            new GeneratePrimeAThread(remainingStrength).run();
            new GeneratePrimeBThread(remainingStrength).run();
        }
        else
        {
            final Vector threads = new Vector();
            for (int i = 0; i < PROCESSOR_CNT / 2; i++)
            {
                final Thread t = new GeneratePrimeAThread(remainingStrength);
                threads.add(t);
            }
            for (int i = PROCESSOR_CNT / 2; i < PROCESSOR_CNT; i++)
            {
                final Thread t = new GeneratePrimeBThread(remainingStrength);
                threads.add(t);
            }
            for (int i = 0; i < threads.size(); i++)
            {
                final Thread t = (Thread) threads.get(i);
                t.start();
            }
            synchronized (waitFor)
            {
                while (a == null || b == null)
                {
                    try
                    {
                        waitFor.wait();
                        // Here Thread.stop() is once useful :)
                        if (a != null)
                        {
                            for (int i = 0; i < PROCESSOR_CNT / 2; i++)
                            {
                                Thread t = (Thread) threads.get(i);
                                t.stop();
                            }
                        }
                        if (b != null)
                        {
                            for (int i = PROCESSOR_CNT / 2; i < PROCESSOR_CNT; i++)
                            {
                                Thread t = (Thread) threads.get(i);
                                t.stop();
                            }
                        }
                    }
                    catch (InterruptedException e)
                    {
                    }
                }
            }
        }

    }

    private void generatePQ()
    {
        // parallelize the generation of p and q
        for (int i = 0; i < PROCESSOR_CNT; i++)
        {
            Thread t = new GeneratePQThread();
            threads.add(t);
        }
        synchronized (threads)
        {
            for (int i = 0; i < threads.size(); i++)
            {
                Thread t = (Thread) threads.get(i);
                t.start();
            }
        }

        // wait for one thread to notify us of the correct primes
        synchronized (waitFor)
        {
            while (p == null)
            {
                try
                {
                    waitFor.wait();
                }
                catch (InterruptedException e)
                {
                }
            }
        }

        // stop all threads and clear thread vector
        synchronized (threads)
        {
            for (int i = 0; i < threads.size(); i++)
            {
                GeneratePQThread pqt = (GeneratePQThread) threads.get(i);
                pqt.endThread();
                try
                {
                    pqt.join();
                }
                catch (InterruptedException e)
                {
                }
            }
            threads.removeAllElements();
        }

    }
    
    private void computeG()
    {
        for (;;)
        {
            computeGParts();

            distribGDivisionTest();

            if (gDivisible)
            {
                continue;
            }

            // make sure that g has order > phi_n/4

            if (g.modPow(phi_n.divide(BigInteger.valueOf(4)), n).equals(
                    BigInteger.ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/4\n g:" + g);
                }
                continue;
            }

            if (g.modPow(phi_n.divide(p_), n).equals(BigInteger.ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/p'\n g: " + g);
                }
                continue;
            }
            if (g.modPow(phi_n.divide(q_), n).equals(BigInteger.ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/q'\n g: " + g);
                }
                continue;
            }
            if (g.modPow(phi_n.divide(a), n).equals(BigInteger.ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/a\n g: " + g);
                }
                continue;
            }
            if (g.modPow(phi_n.divide(b), n).equals(BigInteger.ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/b\n g: " + g);
                }
                continue;
            }
            break;
        }
    }

    private void computeGParts()
    {
        gParts.clear();
        // Prepare threads that compute g
        for (int ind = 0; ind != smallPrimes.size(); ind++)
        {
            BigInteger smallPrime = (BigInteger) smallPrimes.elementAt(ind);
            Thread t = new ComputeGPart(smallPrime);
            synchronized (threads)
            {
                threads.add(t);
            }
        }

        Vector runningThreads = new Vector();
        // start as many as necessary
        synchronized (threads)
        {
            for (int i = 0; i < threads.size() && i < PROCESSOR_CNT; i++)
            {
                Thread t = (Thread) threads.get(i);
                runningThreads.add(t);
                t.start();
            }
        }

        // wait for them to return
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
                    Thread t = (Thread) threads.get(i);
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
            Thread t = (Thread) runningThreads.get(i);
            try
            {
                t.join();
            }
            catch (InterruptedException e)
            {
            }
        }

        if (debug)
        {
            System.out.println("all threads for generating g finished");
        }

        // compute g from them
        g = BigInteger.ONE;
        Enumeration en = gParts.keys();
        while (en.hasMoreElements())
        {
            BigInteger smallPrime = (BigInteger) en.nextElement();
            BigInteger gPart = (BigInteger) gParts.get(smallPrime);
            g = g.multiply(
                    ((BigInteger) gPart).modPow(sigma
                            .divide((BigInteger) smallPrime), n)).mod(n);
        }

    }

    private void distribGDivisionTest()
    {
        // make sure that g is not divisible by p_i or q_i
        gDivisible = false;
        for (int i = 0; i < smallPrimes.size(); i++)
        {
            // Usually (>99%) the test returns false, thus running it in
            // parallel increases speed on multi-processor platforms

            // prepare all threads
            Thread t = new GDivisionTest((BigInteger) smallPrimes.get(i));
            threads.add(t);
        }
        Vector runningThreads = new Vector();
        // start as many as needed
        for (int i = 0; i < threads.size() && i < PROCESSOR_CNT; i++)
        {
            Thread t = (Thread) threads.get(i);
            runningThreads.add(t);
            t.start();
        }

        while (threads.size() > 0)
        {
            synchronized (waitFor)
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
                    Thread t = (Thread) threads.get(i);
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
            Thread t = (Thread) runningThreads.get(i);
            try
            {
                t.join();
            }
            catch (InterruptedException e)
            {
                // TODO Auto-generated catch block
            }
        }
    }

    /**
     * Finds the first 'count' primes starting with 3
     * 
     * @param count
     *            the number of primes to find
     * @return a vector containing the found primes as Integer
     */
    private static Vector findFirstPrimes(final int count)
    {
        final Vector primes = new Vector(count);

        final int[] smallPrimes = getFirstPrimes(count + 1);
        for (int i = 1; i != count + 1; i++)
        {
            primes.addElement(BigInteger.valueOf(smallPrimes[i]));
        }

        return primes;
    }

    /**
     * Generates P and Q for encryption
     * 
     * @author lippold Published under the GPLv2 Licence (c) 2006 Georg Lippold
     * 
     */
    class GeneratePQThread extends Thread
    {

        boolean running = true;

        GeneratePQThread()
        {
            super();
        }

        public void run()
        {
            BigInteger p_, q_, p, q;
            while (running)
            {
                p_ = generatePrime(24, certainty, rand);
                q_ = generatePrime(24, certainty, rand);
                p = computeP(a, u, p_);
                q = computeP(b, v, q_);
                if (p_.equals(q_))
                {
                    // System.out.println("p_ == q_ : " + p_ + q_);
                    continue;
                }
                if (!sigma.gcd(p_.multiply(q_)).equals(BigInteger.ONE))
                {
                    // System.out.println("sigma.gcd(p_.mult(q_)) != 1!\n p_: "
                    // + p_
                    // +"\n q_: "+ q_ );
                    continue;
                }
                if (!p.isProbablePrime(certainty))
                {
                    // System.out.println("p is not prime: " + p);
                    continue;
                }
                if (!q.isProbablePrime(certainty))
                {
                    // System.out.println("q is not prime: " + q);
                    continue;
                }
                if (p.multiply(q).bitLength() < strength)
                {
                    if (debug)
                    {
                        System.out.println("key size too small. Should be "
                                + strength + " but is actually "
                                + p.multiply(q).bitLength());
                    }
                    continue;
                }
                submitPQ(p, q, p_, q_);
                running = false;
            }

        }

        public void endThread()
        {
            running = false;
        }

    }

    /**
     * Computes a BigInteger to assemble G from.
     * 
     * @author lippold Published under the GPLv2 Licence (c) 2006 Georg Lippold
     * 
     */
    class ComputeGPart extends Thread
    {

        private final BigInteger smallPrime;

        private BigInteger gPart;

        ComputeGPart(BigInteger smallPrime)
        {
            super();
            this.smallPrime = smallPrime;
        }

        public void run()
        {
            if (debug)
            {
                System.out.println("computing gPart for " + smallPrime);
            }

            for (;;)
            {
                gPart = new BigInteger(strength, certainty, rand);
                if (gPart.modPow(phi_n.divide(smallPrime), n).equals(
                        BigInteger.ONE))
                {
                    continue;
                }
                if (debug)
                {
                    System.out.println("Prime " + smallPrime + " submitting "
                            + gPart);
                }
                submitGPart(this);
                break;
            }
        }
    }

    /**
     * Tests if g is divisible by a small prime.
     * 
     * @author lippold Published under the GPLv2 Licence (c) 2006 Georg Lippold
     * 
     */
    class GDivisionTest extends Thread
    {
        private final BigInteger smallPrime;

        GDivisionTest(BigInteger smallPrime)
        {
            super();
            this.smallPrime = smallPrime;
        }

        public void run()
        {
            if (g.modPow(phi_n.divide((BigInteger) smallPrime), n).equals(
                    BigInteger.ONE))
            {
                if (debug)
                {
                    System.out.println("g has order phi(n)/" + smallPrime
                            + "\n g: " + g);
                }
                submitDivisionTest(true, this);
            }
            else
            {
                if (debug)
                {
                    System.out.println("Prime " + smallPrime + " finished.");
                }
                submitDivisionTest(false, this);
            }
        }

    }

    class GeneratePrimeAThread extends Thread
    {
        private boolean running = true;

        private final int bits;

        GeneratePrimeAThread(int bits)
        {
            this.bits = bits;
        }

        public void run()
        {
            if (debug)
            {
                System.out.println("Generating a with " + bits
                        + " bit and certainty 2^(-" + certainty + ").");
            }

            BigInteger p_ = new BigInteger(bits, certainty, rand);
            while (p_.bitLength() != bits && running)
            {
                p_ = new BigInteger(bits, certainty, rand);
            }
            a = p_;
            synchronized (waitFor)
            {
                waitFor.notifyAll();
            }

        }

        public void endThread()
        {
            running = false;
        }

    }

    class GeneratePrimeBThread extends Thread
    {
        private boolean running = true;

        private final int bits;

        GeneratePrimeBThread(int bits)
        {
            this.bits = bits;
        }

        public void run()
        {
            if (debug)
            {
                System.out.println("Generating b with " + bits
                        + " bit and certainty 2^(-" + certainty + ").");
            }

            BigInteger p_ = new BigInteger(bits, certainty, rand);
            while (p_.bitLength() != bits && running)
            {
                p_ = new BigInteger(bits, certainty, rand);
            }
            b = p_;
            synchronized (waitFor)
            {
                waitFor.notifyAll();
            }

        }

        public void endThread()
        {
            running = false;
        }

    }
}
