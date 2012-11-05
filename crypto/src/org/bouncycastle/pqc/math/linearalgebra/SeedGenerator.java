package org.bouncycastle.pqc.math.linearalgebra;

/**
 * This implementation provides a software based seed-generator which useses the
 * multithreading capabilities of Java to get "truly" random bits. It uses two
 * threads A and B. A starts B and sleeps for a certain amount of time (50 ms).
 * Meanwhile B starts counting up a global variable. When A wakes up again it
 * stops B and checks if the content of the global variable is odd (-> generate
 * a '1') or even (-> generate a '0'). This process is repeated for each bit.
 * <p/>
 * The main function is generateSeed(int n) which computes a seed of n bytes.
 * The main idea of the algorithm is based on an idea of Marcus Lippert.
 */
public class SeedGenerator
    implements Runnable
{

    private int counter = 0;

    private static final int MIN_INCREASE = 60;

    private boolean stop = false;

    public synchronized byte[] generateSeed(int numBytes)
    {
        byte[] result = new byte[numBytes];
        counter = 0;
        stop = false;
        int last = 0;
        Thread t = new Thread(this);
        t.start();
        for (int i = (numBytes << 3) - 1; i >= 0; i--)
        {
            while (counter - last <= MIN_INCREASE)
            {
                try
                {
                    Thread.sleep(1);
                }
                catch (InterruptedException e)
                {
                    // expected behaviour
                }
            }
            last = counter;
            int bytepos = i >> 3;
            result[bytepos] <<= 1;
            result[bytepos] |= last & 1;
        }
        stop = true;
        return result;
    }

    public void run()
    {
        while (!stop)
        {
            counter++;
        }

    }

}
