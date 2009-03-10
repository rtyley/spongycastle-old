package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;

/**
 * Generates new SRP verifier for user
 */
public class SRP6VerifierGenerator
{
    private BigInteger g;
    private BigInteger p;
    private Digest digest;

    public SRP6VerifierGenerator()
    {
    }

    /**
     * Initialises generator to create new verifiers
     * @param g The group parameter to use (see DHParametersGenerator)
     * @param p The safe prime to use (see DHParametersGenerator)
     * @param digest The digest to use. The same digest type will need to be used later for the actual authentication
     * attempt. Also note that the final session key size is dependent on the chosen digest.
     */
    public void init(BigInteger g, BigInteger p, Digest digest)
    {
        this.g = g;
        this.p = p;
        this.digest = digest;
    }

    /**
     * Creates a new SRP verifier
     * @param identity The user's identifying information (eg. username)
     * @param password The user's password
     * @param salt The salt to use, generally should be large and random
     * @return A new verifier for use in future SRP authentication
     */
    public BigInteger generateVerifier(byte[] identity, byte[] password, BigInteger salt)
    {
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(identity, 0, identity.length);
        digest.update((byte)58);
        digest.update(password, 0, password.length);
        digest.doFinal(output, 0);

        digest.update(salt.toByteArray(), 0, salt.toByteArray().length);
        digest.update(output, 0, output.length);
        digest.doFinal(output, 0);

        BigInteger x = new BigInteger(output);

        if (x.compareTo(p) >= 0)
        {
            x = x.mod(p.subtract(BigInteger.ONE));
        }

        return g.modPow(x, p);
    }
}

