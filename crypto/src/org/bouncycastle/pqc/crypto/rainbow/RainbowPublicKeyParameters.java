package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;

public class RainbowPublicKeyParameters
    extends RainbowKeyParameters
{
    private short[][] coeffquadratic;
    private short[][] coeffsingular;
    private short[] coeffscalar;
    private int docLength; // length of possible document to sign

    /**
     * Constructor
     *
     * @param docLength
     * @param coeffQuadratic
     * @param coeffSingular
     * @param coeffScalar
     */
    public RainbowPublicKeyParameters(int docLength,
                                      short[][] coeffQuadratic, short[][] coeffSingular,
                                      short[] coeffScalar, RainbowParameters params)
    {
        super(false, params);
        this.docLength = docLength;
        this.coeffquadratic = coeffQuadratic;
        this.coeffsingular = coeffSingular;
        this.coeffscalar = coeffScalar;

    }

    /**
     * It constructs internal
     * data types out of these bytes got from ASN.1 decoding.
     *
     * @param docLength
     * @param coeffQuadratic
     * @param coeffSingular
     * @param coeffScalar
     */
    public RainbowPublicKeyParameters(int docLength,
                                      byte[][] coeffQuadratic, byte[][] coeffSingular, byte[] coeffScalar, RainbowParameters params)
    {
        super(false, params);
        this.docLength = docLength;
        this.coeffquadratic = RainbowUtil.convertArray(coeffQuadratic);
        this.coeffsingular = RainbowUtil.convertArray(coeffSingular);
        this.coeffscalar = RainbowUtil.convertArray(coeffScalar);
    }

    /**
     * @return name of the algorithm - "Rainbow"
     */
    public final String getAlgorithm()
    {
        return "Rainbow";
    }

    /**
     * @return the docLength
     */
    public int getDocLength()
    {
        return this.docLength;
    }

    /**
     * @return the coeffquadratic
     */
    public short[][] getCoeffQuadratic()
    {
        return coeffquadratic;
    }

    /**
     * @return the coeffsingular
     */
    public short[][] getCoeffSingular()
    {
        return coeffsingular;
    }

    /**
     * @return the coeffscalar
     */
    public short[] getCoeffScalar()
    {
        return coeffscalar;
    }
}
