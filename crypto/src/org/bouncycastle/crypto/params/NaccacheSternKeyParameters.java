package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/**
 * Public key parameters for NaccacheStern cipher. For details on this cipher,
 * please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
 */
public class NaccacheSternKeyParameters extends AsymmetricKeyParameter
{

    private BigInteger g;

    private BigInteger n;

    private BigInteger sigma;

    /**
     * Construct a NaccacheStern public key.
     * 
     * @param g
     *            the public enryption parameter g
     * @param n
     *            the public modulus n = p*q
     * @param sigma
     *            the public sigma up to which data can be encrypted
     */
    public NaccacheSternKeyParameters(BigInteger g, BigInteger n,
            BigInteger sigma)
    {
        this(false, g, n, sigma);
    }

    /**
     * Construct a NaccacheStern public key.
     * 
     * @param privateKey
     *            should be set to false. For private keys, see
     *            NaccacheSternPrivateKeyParameters.
     * @param g
     *            the public enryption parameter g
     * @param n
     *            the public modulus n = p*q
     * @param sigma
     *            the public sigma up to which data can be encrypted
     */
    public NaccacheSternKeyParameters(boolean privateKey, BigInteger g,
            BigInteger n, BigInteger sigma)
    {
        super(privateKey);
        this.g = g;
        this.n = n;
        this.sigma = sigma;
    }

    /**
     * @return Returns the g.
     */
    public BigInteger getG()
    {
        return g;
    }

    /**
     * @return Returns the lowerSigmaBound.
     */
    public BigInteger getSigma()
    {
        return sigma;
    }

    /**
     * @return Returns the n.
     */
    public BigInteger getModulus()
    {
        return n;
    }

    public String toString()
    {
        String retval = "";
        retval += "Modulus:.... " + n + "\n";
        retval += "g:.......... " + g + "\n";
        retval += "Sigma:...... " + sigma + "\n";
        return retval;
    }

}
