package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;

/**
 * Implements the server side SRP-6 protocol. Note that this class is stateful, and therefore NOT threadsafe.
 * This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
 * "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
 */
public class SRP6Server
{
    private static final BigInteger K = new BigInteger("3");

    private BigInteger g;
    private BigInteger p;
    private BigInteger verifier;

    private SecureRandom random;
    private Digest digest;

    private BigInteger A;

    private BigInteger B;
    private BigInteger b;

    private BigInteger S;
    private BigInteger M1;

    public SRP6Server()
    {
    }

    /**
     * Initialises the server to accept a new client authentication attempt
     * @param g The group parameter associated with the client's verifier
     * @param p The safe prime associated with the client's verifier
     * @param verifier The client's verifier
     * @param digest The digest algorithm associated with the client's verifier
     * @param random For key generation
     */
    public void init(BigInteger g, BigInteger p, BigInteger verifier, Digest digest, SecureRandom random)
    {
        this.g = g;
        this.p = p;
        this.verifier = verifier;

        this.random = random;
        this.digest = digest;
    }

    /**
     * Generates the server's credentials that are to be sent to the client.
     * @return The server's credentials to the client
     */
    public BigInteger generateServerCredentials()
    {

        //Make sure b > log base g of p, infinitesimal chance of this, but check is trivial
        BigInteger log = log(g, p);

        while (true)
        {
            this.b = new BigInteger(digest.getDigestSize(), random);
            if (this.b.compareTo(log) > 0)
            {
                break;
            }
        }

        BigInteger constant = K.multiply(verifier);

        BigInteger exponent = g.modPow(b, p);

        this.B = constant.add(exponent).mod(p);

        return B;
    }

    /**
     * Processes the client's credentials and verification message.  If valid the shared session key is generated and returned.
     * @param A The client's credentials
     * @param M1 The client's verification message
     * @return A random shared session key
     * @throws CryptoException If client's credentials are invalid
     */
    public byte[] processClientCredentialsAndGenerateSessionKey(BigInteger A, BigInteger M1) throws CryptoException
    {
        //Check that A is != 0 mod p
        if (BigInteger.ZERO.equals(A) || BigInteger.ZERO.equals(p.mod(A)))
        {
            throw new CryptoException("Client credentials invalid");
        }

        this.A = A;
        this.M1 = M1;

        BigInteger u = calculateU();
        this.S = calculateS(u);

        if (!verifyClient())
        {
            throw new CryptoException("Client credentials invalid");
        }

        return generateSessionKey();
    }

    /**
     * If server verification is required by the client, generates the server's verification message
     * @return The server's verification message for the client
     * @throws CryptoException If the client's credentials are invalid
     */
    public BigInteger generateServerVerificationMessage() throws CryptoException
    {
        //Make sure client has proved knowledge of S before we do
        if (verifyClient())
        {
            digest.update(A.toByteArray(), 0, A.toByteArray().length);
            digest.update(M1.toByteArray(), 0, M1.toByteArray().length);
            digest.update(S.toByteArray(), 0, S.toByteArray().length);

            byte[] output = new byte[digest.getDigestSize()];
            digest.doFinal(output, 0);

            return new BigInteger(output);
        }
        throw new CryptoException("Client credential invalid");
    }

    private byte[] generateSessionKey() {
        digest.update(S.toByteArray(), 0, S.toByteArray().length);
        byte[] sessionKey = new byte[digest.getDigestSize()];

        digest.doFinal(sessionKey, 0);

        return sessionKey;
    }

    private BigInteger calculateU()
    {
        digest.update(A.toByteArray(), 0, A.toByteArray().length);
        digest.update(B.toByteArray(), 0, B.toByteArray().length);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        return new BigInteger(output);
    }

    private BigInteger calculateS(BigInteger u)
    {
        BigInteger S = verifier.modPow(u, p);
        S = S.multiply(A);

        return S.modPow(b, p);
    }

    private boolean verifyClient()
    {
        digest.update(A.toByteArray(), 0, A.toByteArray().length);
        digest.update(B.toByteArray(), 0, B.toByteArray().length);
        digest.update(S.toByteArray(), 0, S.toByteArray().length);

        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);

        BigInteger M1expected = new BigInteger(output);

        return M1expected.equals(M1);
    }

    // Gets an upper bound of the log of any number with an arbitrary base
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

