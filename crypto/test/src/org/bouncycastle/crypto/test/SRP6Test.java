package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.util.test.SimpleTest;

public class SRP6Test extends SimpleTest
{
    private static final BigInteger G = new BigInteger("81178965863511021384719124640754141125");
    private static final BigInteger P = new BigInteger("278734377450504368714014319060979494183");

    private static final byte[] IDENTITY = "username".getBytes();
    private static final byte[] PASSWORD = "password".getBytes();
    private static final BigInteger SALT = new BigInteger(IDENTITY);

    private static final BigInteger CLIENT_VERIFIER = new BigInteger("58003286200829921368127787898977445244");

    public String getName()
    {
        return "SRP6";
    }

    public void performTest() throws Exception
    {
        testSRPVerifierGenerator();
        testClientVerification(G, P, CLIENT_VERIFIER);
        testMutualVerification(G, P, CLIENT_VERIFIER);
        testClientVerificationFails(G, P, CLIENT_VERIFIER);
        testServerVerificationFails(G, P, CLIENT_VERIFIER);
        testDHParamInput();
    }

    private void testSRPVerifierGenerator()
    {
        SRP6VerifierGenerator generator = new SRP6VerifierGenerator();
        generator.init(G, P, new SHA256Digest());

        BigInteger verifier = generator.generateVerifier(IDENTITY, PASSWORD, SALT);

        if (!CLIENT_VERIFIER.equals(verifier))
        {
            fail("SRP verifier generator test failed.  Expected: " + CLIENT_VERIFIER + " Actual: " + verifier);
        }
    }

    private void testMutualVerification(BigInteger g, BigInteger p, BigInteger verifier)
    {
        try
        {
            SecureRandom random = new SecureRandom();

            SRP6Server server = new SRP6Server();
            server.init(g, p, verifier, new SHA256Digest(), random);

            BigInteger B = server.generateServerCredentials();


            SRP6Client client = new SRP6Client();
            client.init(g, p, new SHA256Digest(), random);

            BigInteger A = client.generateClientCredentials(SALT, IDENTITY, PASSWORD);
            BigInteger M1 = client.generateClientVerificationMessage(B);

            byte[] serverSessionKey = server.processClientCredentialsAndGenerateSessionKey(A, M1);
            BigInteger M2 = server.generateServerVerificationMessage();

            byte[] clientSessionKey = client.verifyServerAndGenerateSessionKey(M2);

            if (serverSessionKey.length != clientSessionKey.length)
            {
                fail("SRP key exchange failed, session keys not equal");
            }
            for (int i = 0; i < serverSessionKey.length; i++)
            {
                if (serverSessionKey[i] != clientSessionKey[i])
                {
                    fail("SRP key exchange failed, session keys not equal");
                }
            }
            if (serverSessionKey.length != 32)
            {
                fail("SRP key exchange failed - session key not expected length");
            }

        }
        catch (CryptoException e)
        {
            fail("SRP key exchange failed");
        }
    }

    private void testClientVerification(BigInteger g, BigInteger p, BigInteger verifier)
    {
        try
        {
            SecureRandom random = new SecureRandom();

            SRP6Server server = new SRP6Server();
            server.init(g, p, verifier, new SHA256Digest(), random);

            BigInteger B = server.generateServerCredentials();


            SRP6Client client = new SRP6Client();
            client.init(g, p, new SHA256Digest(), random);

            BigInteger A = client.generateClientCredentials(SALT, IDENTITY, PASSWORD);
            BigInteger M1 = client.generateClientVerificationMessage(B);

            byte[] serverSessionKey = server.processClientCredentialsAndGenerateSessionKey(A, M1);

            byte[] clientSessionKey = client.verifyServerAndGenerateSessionKey(null);

            if (serverSessionKey.length != clientSessionKey.length)
            {
                fail("SRP key exchange failed, session keys not equal");
            }
            for (int i = 0; i < serverSessionKey.length; i++)
            {
                if (serverSessionKey[i] != clientSessionKey[i])
                {
                    fail("SRP key exchange failed, session keys not equal");
                }
            }
            if (serverSessionKey.length != 32)
            {
                fail("SRP key exchange failed - session key not expected length");
            }

        }
        catch (CryptoException e)
        {
            e.printStackTrace();
            fail("SRP key exchange failed");
        }
    }

    private void testClientVerificationFails(BigInteger g, BigInteger p, BigInteger verifier)
    {
        try
        {
            SecureRandom random = new SecureRandom();

            SRP6Server server = new SRP6Server();
            server.init(g, p, verifier, new SHA256Digest(), random);

            BigInteger B = server.generateServerCredentials();


            SRP6Client client = new SRP6Client();
            client.init(g, p, new SHA256Digest(), random);

            BigInteger A = client.generateClientCredentials(SALT, IDENTITY, "wrongPassword".getBytes());
            BigInteger M1 = client.generateClientVerificationMessage(B);

            try
            {
                server.processClientCredentialsAndGenerateSessionKey(A, M1);
                fail("SRP key exchange passed with wrong password");
            }
            catch (CryptoException e)
            {
            }
        }
        catch (CryptoException e)
        {
            fail("SRP key exchange failed");
        }
    }

    private void testServerVerificationFails(BigInteger g, BigInteger p, BigInteger verifier)
    {
        try
        {
            SecureRandom random = new SecureRandom();

            SRP6Server server = new SRP6Server();
            server.init(g, p, verifier, new SHA256Digest(), random);

            BigInteger B = server.generateServerCredentials();


            SRP6Client client = new SRP6Client();
            client.init(g, p, new SHA256Digest(), random);

            BigInteger A = client.generateClientCredentials(SALT, IDENTITY, PASSWORD);
            BigInteger M1 = client.generateClientVerificationMessage(B);

            server.processClientCredentialsAndGenerateSessionKey(A, M1);

            BigInteger M2 = server.generateServerVerificationMessage().add(BigInteger.ONE);

            try
            {
                client.verifyServerAndGenerateSessionKey(M2);
                fail("SRP key exchange passed with invalid server verification message");
            }
            catch (CryptoException e)
            {
            }
        }
        catch (CryptoException e)
        {
            fail("SRP key exchange failed");
        }
    }

    private void testDHParamInput()
    {
        DHParametersGenerator paramGen = new DHParametersGenerator();
        paramGen.init(128, 10, new SecureRandom());
        DHParameters parameters = paramGen.generateParameters();

        BigInteger g = parameters.getG();
        BigInteger p = parameters.getP();

        SRP6VerifierGenerator srpVerifierGenerator = new SRP6VerifierGenerator();
        srpVerifierGenerator.init(g, p, new SHA256Digest());

        BigInteger verifier = srpVerifierGenerator.generateVerifier(IDENTITY, PASSWORD, SALT);

        testMutualVerification(g, p, verifier);
    }

    public static void main(String[] args)
    {
        runTest(new SRP6Test());
    }
}

