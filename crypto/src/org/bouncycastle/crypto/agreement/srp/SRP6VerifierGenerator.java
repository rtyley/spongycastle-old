package org.bouncycastle.crypto.agreement.srp;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;

/**
 * Generates new SRP verifier for user
 */
public class SRP6VerifierGenerator
{
    private BigInteger g;
    private BigInteger N;
    private Digest digest;

    public SRP6VerifierGenerator()
    {
    }

    /**
     * Initialises generator to create new verifiers
     * @param g The group parameter to use (see DHParametersGenerator)
     * @param N The safe prime to use (see DHParametersGenerator)
     * @param digest The digest to use. The same digest type will need to be used later for the actual authentication
     * attempt. Also note that the final session key size is dependent on the chosen digest.
     */
    public void init(BigInteger g, BigInteger N, Digest digest)
    {
        this.g = g;
        this.N = N;
        this.digest = digest;
    }

    /**
     * Creates a new SRP verifier
     * @param salt The salt to use, generally should be large and random
     * @param identity The user's identifying information (eg. username)
     * @param password The user's password
     * @return A new verifier for use in future SRP authentication
     */
    public BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password)
    {
    	BigInteger x = SRP6Util.calculateX(digest, N, salt, identity, password);

        return g.modPow(x, N);
    }
}
