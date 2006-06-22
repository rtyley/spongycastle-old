package org.bouncycastle.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.generators.NaccacheSternKeyPairGenerator;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test case for NaccacheStern cipher. For details on this cipher, please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 * 
 * Performs the following tests:
 * <ul>
 * <li> Toy example from the NaccacheSternPaper </li>
 * <li> 768 bit test with text "Now is the time for all good men." (ripped from
 * RSA test) and the same test with the first byte replaced by 0xFF </li>
 * <li> 1024 bit test analog to 768 bit test </li>
 * </ul>
 */
public class NaccacheSternTest extends SimpleTest
{

    boolean debug = false;

    static final SecureRandom random = new SecureRandom();
    
    // Always use 2 threads, otherwise synchronization problems are not detected
    static final NaccacheSternEngine cryptEng = new NaccacheSternEngine(2);

    // Always use 2 threads, otherwise synchronization problems are not detected
    static final NaccacheSternEngine decryptEng = new NaccacheSternEngine(2);

    // static final BigInteger paperTest = BigInteger.valueOf(202);

    static final String input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

    static final BigInteger paperTest = BigInteger.valueOf(202);

    //
    // to check that we handling byte extension by big number correctly.
    //
    static final String edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

    public String getName()
    {
        return "NaccacheStern";
    }

    public void performTest()
    {
        Date start = new Date();
        // Set debug Parameters in Engine accordingly
        decryptEng.setDebug(debug);
        cryptEng.setDebug(debug);

        // Test with given key from NaccacheSternPaper (totally insecure)

        // First the Parameters from the NaccacheStern Paper
        // (see http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf )

        doPaperTest();

        // 768 Bit Test with on the fly generated key
        // 
        test(768, true);

        // 1024 Bit Test with pre-generated key
        // 
        test(1024, false);

        // END OF TEST CASE
        if (debug)
        {
            System.out.println("All tests successful");
            Date finish = new Date();
            long runtime = finish.getTime() - start.getTime();
            long seconds = runtime / 1000;
            long minutes = seconds / 60;
            long hours = seconds / 3600;
            System.out.println("Tests took " + hours + "h " + minutes % 60
                    + "m " + seconds % 60 + "s");
        }

    }

    private void test(int strength, boolean staticKey)
    {
        // 
        // Performs a cipher test with the given strength
        //

        if (debug)
        {
            System.out.println();
            System.out.println(strength + " Bit TEST");
        }

        AsymmetricCipherKeyPair pair = null;

        if (staticKey)
        {
            try
            {
                pair = getSerializedKeyPair(strength);
            }
            catch (Exception e)
            {
                String msg = "failed encryption decryption ("
                        + strength
                        + ") test with static key. Reason: no static key available";
                if (debug)
                {
                    System.out.println(msg);
                    System.out.println(e.toString());
                    System.out.println(e.getMessage());
                    System.out.println(e.fillInStackTrace());
                }
                fail(msg);
            }

        }
        else
        {
            // specify key generation parameters
            NaccacheSternKeyGenerationParameters genParam;
            if (debug)
            {
                genParam = new NaccacheSternKeyGenerationParameters(random,
                        strength, 25, strength / 25, true);
            }
            else
            {
                genParam = new NaccacheSternKeyGenerationParameters(random,
                        strength, 25, strength / 25);
            }

            // Initialize Key generator and generate key pair
            // Use always 2 threads for testing synchronization issues
            NaccacheSternKeyPairGenerator pGen = new NaccacheSternKeyPairGenerator(2);
            pGen.init(genParam);

            pair = pGen.generateKeyPair();
        }

        if (((NaccacheSternKeyParameters) pair.getPublic()).getModulus()
                .bitLength() < strength)
        {
            System.out.println("FAILED: key size is <"
                    + strength
                    + " bit, exactly "
                    + ((NaccacheSternKeyParameters) pair.getPublic())
                            .getModulus().bitLength() + " bit");
            fail("failed key generation (" + strength + ") length test");
        }

        // Serialization test
        if (debug)
        {
            System.out.println("Serializing NaccacheSternKeyPair");
        }
        try
        {
            NaccacheSternKeyParameters pub = (NaccacheSternKeyParameters) pair
                    .getPublic();
            NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters) pair
                    .getPrivate();
            byte[] pubSerialized = NaccacheSternKeySerializationFactory
                    .getSerialized(pub);
            byte[] privSerialized = NaccacheSternKeySerializationFactory
                    .getSerialized(priv);

            if (debug && !staticKey)
            {
                System.out.println("Found new NaccacheSternPublicKey:");
                System.out.println(new String(Base64.encode(pubSerialized)));
                System.out.println("Found new NaccacheSternPrivateKey:");
                System.out.println(new String(Base64.encode(privSerialized)));
            }

            NaccacheSternKeyParameters pubCloned = NaccacheSternKeySerializationFactory
                    .deserialize(pubSerialized);
            NaccacheSternPrivateKeyParameters privCloned = (NaccacheSternPrivateKeyParameters) NaccacheSternKeySerializationFactory
                    .deserialize(privSerialized);
            if (!(pubCloned.getG().equals(pub.getG())
                    && pubCloned.getSigma().equals(pub.getSigma()) && pubCloned
                    .getModulus().equals(pub.getModulus())))
            {
                String msg = "Public key serialization failed";
                if (debug)
                {
                    System.out.println(msg);
                }
                fail(msg);
            }
            if (!(privCloned.getLookupTable().equals(priv.getLookupTable())
                    && privCloned.getPhi_n().equals(priv.getPhi_n()) && privCloned
                    .getSmallPrimes().equals(priv.getSmallPrimes())))
            {
                String msg = "Private key serialization failed";
                if (debug)
                {
                    System.out.println(msg);
                }
                fail(msg);
            }
        }
        catch (IOException e)
        {
            if (debug)
            {
                System.out.println(e.toString());
                System.out.println(e.fillInStackTrace());
                System.out.println(e.getMessage());
            }
            fail(e.getMessage());
        }
        catch (ClassNotFoundException e)
        {
            if (debug)
            {
                System.out.println(e.toString());
                System.out.println(e.fillInStackTrace());
                System.out.println(e.getMessage());
            }
            fail(e.getMessage());
        }

        // Initialize Engines with KeyPair

        if (debug)
        {
            System.out.println("initializing " + strength
                    + " bit encryption engine");
        }
        cryptEng.init(true, pair.getPublic());

        if (debug)
        {
            System.out.println("initializing " + strength
                    + " bit decryption engine");
        }
        decryptEng.init(false, pair.getPrivate());

        // Basic data input
        byte[] data = Hex.decode(input);

        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
        {
            fail("failed encryption decryption (" + strength + ") basic test");
        }

        // Data starting with FF byte (would be interpreted as negative
        // BigInteger)

        data = Hex.decode(edgeInput);

        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
        {
            fail("failed encryption decryption (" + strength
                    + ") edgeInput test");
        }

        if (debug)
        {
            System.out.println("initializing " + strength
                    + " bit encryption engine for probabilistic encryption");
        }
        cryptEng.setCertificate(BigInteger.valueOf(10));
        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
        {
            fail("failed probabilistic encryption decryption (" + strength
                    + ") test");
        }

        // Re-Initialize engine for deterministic encryption
        cryptEng.setCertificate(null);

        // Addition Test:
        // decrypt(crypt(m1)*crypt(m2)) = (m1 + m2) % sigma
        // if m1, m2 < sigma
        //
        // Multiplication Test:
        // decrypt( crypt(m1)^m2 ) = (m1*m2) % sigma
        // if m1 < sigma

        if (debug)
        {
            System.out.println();
            System.out.println("Addition & Multiplication Test");
        }

        NaccacheSternKeyParameters pub = (NaccacheSternKeyParameters) pair
                .getPublic();
        BigInteger sigma = pub.getSigma();

        // cryptEng.getInputBlockSize() * 8 -1 is necessary because otherwise
        // we would end up with a integer that may have 1 bit too much
        // See also BigInteger(int, Random);
        BigInteger m1 = new BigInteger(cryptEng.getInputBlockSize() * 8 - 1,
                random);
        BigInteger m2 = new BigInteger(cryptEng.getInputBlockSize() * 8 - 1,
                random);

        if (debug)
        {
            System.out.println("m1: ....................... " + m1);
            System.out.println("m2: ....................... " + m2);
        }

        try
        {
            byte[] cryptM1 = cryptEng.processData(m1.toByteArray());
            byte[] cryptM2 = cryptEng.processData(m2.toByteArray());
            byte[] addOutput = cryptEng.addCryptedBlocks(cryptM1, cryptM2);
            byte[] multOutput = cryptEng.multiplyCryptedBlock(cryptM1, m2);

            BigInteger m1AddM2 = new BigInteger(1, decryptEng
                    .processData(addOutput));
            BigInteger m1MultM2 = new BigInteger(1, decryptEng
                    .processData(multOutput));
            if (debug)
            {
                System.out.println("(m1 + m2 ) % sigma " + m1AddM2);
                System.out.println("(m1 * m2:) % sigma " + m1MultM2);
            }
            if (!m1AddM2.equals(m1.add(m2).mod(sigma)))
            {
                if (debug)
                {
                    System.out.println("(m1 + m2)%sigma is\n"
                            + m1.add(m2).mod(sigma)
                            + "\nbut the decryption returned\n" + m1AddM2);
                }
                fail("failed encryption decryption (" + strength
                        + ") Addition test");
            }
            if (!m1MultM2.equals(m1.multiply(m2).mod(sigma)))
            {
                if (debug)
                {
                    System.out.println("(m1 * m2)%sigma is\n"
                            + m1.multiply(m2).mod(sigma)
                            + "\nbut the decryption returned\n" + m1MultM2);
                }
                fail("failed encryption decryption (" + strength
                        + ") Multiplication test");
            }
        }
        catch (InvalidCipherTextException e)
        {
            if (debug)
            {
                System.out.println("got invalid cipher text exception");
                System.out.println(e.toString());
            }
            fail("failed encryption decryption (" + strength
                    + ") Addtion & Multiplication test");
        }

    }

    private byte[] enDeCrypt(byte[] input)
    {

        // create work array
        byte[] data = new byte[input.length];
        System.arraycopy(input, 0, data, 0, data.length);

        // Perform encryption like in the paper from Naccache-Stern
        if (debug)
        {
            System.out.println("encrypting data. Data representation\n"
            // + "As String:.... " + new String(data) + "\n"
                    + "As BigInteger: " + new BigInteger(1, data));
            System.out.println("data length is " + data.length);
        }

        try
        {
            data = cryptEng.processData(data);
        }
        catch (InvalidCipherTextException e)
        {
            if (debug)
            {
                System.out.println("failed - exception " + e.toString() + "\n"
                        + e.getMessage());
            }
            fail("failed - exception " + e.toString() + "\n" + e.getMessage());
        }

        if (debug)
        {
            System.out.println("enrypted data representation\n"
            // + "As String:.... " + new String(data) + "\n"
                    + "As BigInteger: " + new BigInteger(1, data));
            System.out.println("data length is " + data.length);
        }

        try
        {
            data = decryptEng.processData(data);
        }
        catch (InvalidCipherTextException e)
        {
            if (debug)
            {
                System.out.println("failed - exception " + e.toString() + "\n"
                        + e.getMessage() + "\n");
            }
            fail("failed - exception " + e.toString() + "\n" + e.getMessage()
                    + "\n");
        }

        if (debug)
        {
            System.out.println("decrypted data representation\n"
            // + "As String:.... " + new String(data) + "\n"
                    + "As BigInteger: " + new BigInteger(1, data));
            System.out.println("data length is " + data.length);
        }

        return data;

    }

    /**
     * Returns a predefined NaccacheSternKeyPair.
     * 
     * @return a pre-generated NaccacheSternKeyPair.
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private static AsymmetricCipherKeyPair getSerializedKeyPair(int size)
            throws IOException, ClassNotFoundException
    {
        InputStream is = NaccacheSternTest.class.getResourceAsStream("NaccSt"
                + size + "BitPriv.txt");
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String keyStr = br.readLine();
        byte[] keyData = Base64.decode(keyStr.getBytes());
        NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters) NaccacheSternKeySerializationFactory
                .deserialize(keyData);

        is = NaccacheSternTest.class.getResourceAsStream("NaccSt" + size
                + "BitPub.txt");
        br = new BufferedReader(new InputStreamReader(is));
        keyStr = br.readLine();
        keyData = Base64.decode(keyStr.getBytes());
        NaccacheSternKeyParameters pub = NaccacheSternKeySerializationFactory
                .deserialize(keyData);

        return new AsymmetricCipherKeyPair(pub, priv);

    }

    private void doPaperTest()
    {
        // Values from NaccacheStern paper
        BigInteger a = BigInteger.valueOf(101);
        BigInteger u1 = BigInteger.valueOf(3);
        BigInteger u2 = BigInteger.valueOf(5);
        BigInteger u3 = BigInteger.valueOf(7);

        BigInteger b = BigInteger.valueOf(191);
        BigInteger v1 = BigInteger.valueOf(11);
        BigInteger v2 = BigInteger.valueOf(13);
        BigInteger v3 = BigInteger.valueOf(17);

        BigInteger TWO = BigInteger.valueOf(2);
        BigInteger paperSigma = u1.multiply(u2).multiply(u3).multiply(v1)
                .multiply(v2).multiply(v3);

        BigInteger p = TWO.multiply(a).multiply(u1).multiply(u2).multiply(u3)
                .add(BigInteger.ONE);

        BigInteger q = TWO.multiply(b).multiply(v1).multiply(v2).multiply(v3)
                .add(BigInteger.ONE);

        BigInteger n = p.multiply(q);

        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(
                q.subtract(BigInteger.ONE));

        BigInteger g = BigInteger.valueOf(131);

        Vector paperSmallPrimes = new Vector();
        paperSmallPrimes.add(u1);
        paperSmallPrimes.add(u2);
        paperSmallPrimes.add(u3);
        paperSmallPrimes.add(v1);
        paperSmallPrimes.add(v2);
        paperSmallPrimes.add(v3);

        NaccacheSternKeyParameters pubParameters = new NaccacheSternKeyParameters(
                false, g, n, paperSigma);

        NaccacheSternPrivateKeyParameters privParameters = new NaccacheSternPrivateKeyParameters(
                g, n, paperSigma, paperSmallPrimes, phi_n, debug, 2);

        AsymmetricCipherKeyPair pair = new AsymmetricCipherKeyPair(
                pubParameters, privParameters);
        // Initialize Engines with KeyPair

        if (debug)
        {
            System.out.println("initializing encryption engine");
        }
        cryptEng.init(true, pair.getPublic());

        if (debug)
        {
            System.out.println("initializing decryption engine");
        }
        decryptEng.init(false, pair.getPrivate());

        byte[] data = paperTest.toByteArray();

        if (!new BigInteger(1, data).equals(new BigInteger(1, enDeCrypt(data))))
        {
            fail("failed NaccacheStern paper test");
        }

    }

    public static void main(String[] args)
    {
        runTest(new NaccacheSternTest());
//        NaccacheSternTest nst = new NaccacheSternTest();
//        nst.debug = true;
//        nst.performTest();
    }
}
