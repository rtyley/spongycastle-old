package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

/**
 * Implements the client side SRP-6 protocol. Note that this class is stateful, and therefore NOT threadsafe.
 * This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
 */
public class SRP6Client
{
    private static final BigInteger K = new BigInteger("3");

    private BigInteger g;
    private BigInteger p;

    private BigInteger a;
    private BigInteger A;

    private BigInteger x;
    private BigInteger u;

    private BigInteger M1;

    private BigInteger S;

    private Digest digest;
    private SecureRandom random;

    public SRP6Client()
    {
    }

    /**
     * Initialises the client to begin new authentication attempt
     * @param g The group parameter associated with the client's verifier
     * @param p The safe prime associated with the client's verifier
     * @param digest The digest algorithm associated with the client's verifier
     * @param random For key generation
     */
    public void init(BigInteger g, BigInteger p, Digest digest, SecureRandom random)
    {
        this.g = g;
        this.p = p;
        this.digest = digest;
        this.random = random;
    }

    /**
     * Generates client's credentials given the client's salt, identity and password
     * @param salt The salt used in the client's verifier.
     * @param identity The user's identity (eg. username)
     * @param password The user's password
     * @return Client's credentials for the server
     */
    public BigInteger generateClientCredentials(BigInteger salt, byte[] identity, byte[] password)
    {
        calculateX(salt, identity, password);

        //Make sure a > log base g of p, infinitesimal chance of this, but check is trivial
        BigInteger log = log(g, p);

        while (true)
        {
            this.a = new BigInteger(digest.getDigestSize(), random);
            if (this.a.compareTo(log) > 0)
            {
                break;
            }
        }

        A = g.modPow(a, p);

        return A;
    }

    /**
     * Generates client's verification message given the server's credentials
     * @param B The server's credentials
     * @return Client's verification message for the server
     * @throws CryptoException If server's credentials are invalid
     */
    public BigInteger generateClientVerificationMessage(BigInteger B) throws CryptoException
    {
        //Check that B is != 0
        if (BigInteger.ZERO.equals(B) || BigInteger.ZERO.equals(p.mod(B)))
        {
            throw new CryptoException("Server credentials invalid");
        }

        calculateU(B);

        calculateS(B);

        M1 = calculateM1(B);

        return M1;
    }

    /**
     * Verifies that the server knows the shared secret and generates a session key
     * to be used for further communication
     * @param M2 The server's verification message or null if server authentication is not required
     * @return A random shared session key
     * @throws CryptoException If server verification failed
     */
    public byte[] verifyServerAndGenerateSessionKey(BigInteger M2) throws CryptoException
    {

        if (M2 != null)
        {
            BigInteger M2expected = calculateExpectedM2();

            if (M2expected.equals(M2))
            {
                return generateSessionKey();
            }
        }
        else
        {
            return generateSessionKey();
        }

        throw new CryptoException("Server verification failed");
    }

    private byte[] generateSessionKey() {
        digest.update(S.toByteArray(), 0, S.toByteArray().length);
        byte[] sessionKey = new byte[digest.getDigestSize()];

        digest.doFinal(sessionKey, 0);

        return sessionKey;
    }

    private void calculateX(BigInteger salt, byte[] identity, byte[] password)
    {
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(identity, 0, identity.length);
        digest.update((byte)58);
        digest.update(password, 0, password.length);
        digest.doFinal(output, 0);

        digest.update(salt.toByteArray(), 0, salt.toByteArray().length);
        digest.update(output, 0, output.length);
        digest.doFinal(output, 0);

        x = new BigInteger(output);

        if (x.compareTo(p) >= 0)
        {
            x = x.mod(p.subtract(BigInteger.ONE));
        }
    }

    private void calculateU(BigInteger B)
    {
        digest.update(A.toByteArray(), 0, A.toByteArray().length);
        digest.update(B.toByteArray(), 0, B.toByteArray().length);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        u = new BigInteger(output);
    }

    private void calculateS(BigInteger B)
    {
        BigInteger exponent = u.multiply(x).add(a);

        S = g.modPow(x, p);
        S = S.multiply(K);
        S = B.subtract(S);

        S = S.modPow(exponent, p);
    }

    private BigInteger calculateM1(BigInteger B)
    {
        digest.update(A.toByteArray(), 0, A.toByteArray().length);
        digest.update(B.toByteArray(), 0, B.toByteArray().length);
        digest.update(S.toByteArray(), 0, S.toByteArray().length);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }

    private BigInteger calculateExpectedM2()
    {
        digest.update(A.toByteArray(), 0, A.toByteArray().length);
        digest.update(M1.toByteArray(), 0, M1.toByteArray().length);
        digest.update(S.toByteArray(), 0, S.toByteArray().length);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }

    //Gets an upper bound of the log of any number with an arbitrary base
    private static BigInteger log(BigInteger base, BigInteger number)
    {
        int log = 0;
        BigInteger result = number.abs();
        base = base.abs();
        while (true)
        {
            result = result.divide(base);
            log++;
            if (base.compareTo(result) > 0)
            {
                break;
            }
        }
        return new BigInteger(String.valueOf(log + 1));
    }
}

