package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Private key parameters for NaccacheStern cipher. For details on this cipher,
 * please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 */
public class NaccacheSternPrivateKeyParameters extends
        NaccacheSternKeyParameters
{
    private BigInteger phi_n;

    private Vector smallPrimes;

    private Hashtable lookupList;

    private Vector threads;
    
    //private static final int PROCESSOR_CNT = Runtime.getRuntime().availableProcessors();
    private static final int PROCESSOR_CNT = 1;
    
    private boolean debug = false;

    // need a serializable synchronization object here
    private final Vector waitFor = new Vector();

    public NaccacheSternPrivateKeyParameters(BigInteger g, BigInteger n,
            int lowerSigmaBound, Vector smallPrimes, BigInteger phi_n)
    {
        this(g, n, lowerSigmaBound, smallPrimes, phi_n, false);
    }

    /**
     * Constructs a NaccacheSternPrivateKey
     * 
     * @param g
     *            the public enryption parameter g
     * @param n
     *            the public modulus n = p*q
     * @param lowerSigmaBound
     *            the public lower sigma bound up to which data can be encrypted
     * @param smallPrimes
     *            the small primes, of which sigma is constructed in the right
     *            order
     * @param phi_n
     *            the private modulus phi(n) = (p-1)(q-1)
     */
    public NaccacheSternPrivateKeyParameters(BigInteger g, BigInteger n,
            int lowerSigmaBound, Vector smallPrimes, BigInteger phi_n,
            boolean verbose)
    {
        super(true, g, n, lowerSigmaBound);
        this.smallPrimes = smallPrimes;
        this.phi_n = phi_n;
        this.debug = verbose;
        lookupList = new Hashtable();
        if (debug)
        {
            System.out
                    .println("current machine has " + PROCESSOR_CNT + " CPU's");
            System.out.println("Constructing lookup Array");
        }
        threads = new Vector();
        for (int i = 0; i < smallPrimes.size(); i++)
        {
            final BigInteger actualPrime = (BigInteger) smallPrimes.elementAt(i);
            final Thread t = new ConstructLookupVector(actualPrime);
            threads.add(t);
        }
        final Vector runningThreads = new Vector();
        synchronized (threads)
        {
            // Start as many threads as we have processors
            for (int i = 0; i < PROCESSOR_CNT && i < threads.size(); i++)
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
                // TODO Auto-generated catch block
            }
        }
        if (debug)
        {
            System.out
                    .println("NaccacheSternPrivateKey construction finished");
        }

    }

    public BigInteger getPhi_n()
    {
        return phi_n;
    }

    public Vector getSmallPrimes()
    {
        return smallPrimes;
    }

    public Hashtable getLookupTable()
    {
        return lookupList;
    }

    private void submitLookupVector(ConstructLookupVector t)
    {
        synchronized (lookupList)
        {
            lookupList.put(t.smallPrime, t.lookup);
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

    class ConstructLookupVector extends Thread
    {

        final Vector lookup = new Vector();

        final BigInteger smallPrime;

        ConstructLookupVector(BigInteger smallPrime)
        {
            this.smallPrime = smallPrime;
        }

        public void run()
        {
            if (debug)
            {
                System.out.println("Constructing lookup ArrayList for "
                        + smallPrime);
            }
            final BigInteger g = getG();
            final BigInteger modulus = getModulus();
            for (int j = 0; j < smallPrime.intValue(); j++)
            {
                final BigInteger comp = (phi_n.multiply(BigInteger.valueOf(j)))
                        .divide(smallPrime);
                lookup.add(g.modPow(comp, modulus));
            }
            if (debug)
            {
                System.out.println("thread for prime " + smallPrime
                        + " finished.");
            }
            submitLookupVector(this);
        }
    }
    
    public String toString()
    {
        String retval = super.toString();
        retval += "phi_n:...... " + phi_n + "\n";
        retval += "smallPrimes: " + smallPrimes + "\n";
        return retval;
    }
    
}
