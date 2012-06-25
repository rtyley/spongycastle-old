package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;

public class RainbowPrivateKeyParameters
    extends RainbowKeyParameters
{
    /**
     * Constructor
     *
     * @param A1inv  the inverse of A1(the matrix part of the affine linear map L1)
     *               (n-v1 x n-v1 matrix)
     * @param b1     translation vector, part of the linear affine map L1
     * @param A2inv  the inverse of A2(the matrix part of the affine linear map L2)
 *               (n x n matrix)
     * @param b2     translation vector, part of the linear affine map L2
     * @param vi     the number of Vinegar-variables per layer
     * @param layers the polynomials with their coefficients of private map F
     */
    public RainbowPrivateKeyParameters(short[][] A1inv, short[] b1,
                                       short[][] A2inv, short[] b2, int[] vi, Layer[] layers, RainbowParameters params)
    {
        super(true, params);

        this.A1inv = A1inv;
        this.b1 = b1;
        this.A2inv = A2inv;
        this.b2 = b2;
        this.vi = vi;
        this.layers = layers;
    }

    /**
     * . It constructs internal
     * data types out of these bytes got from ASN.1 decoding.
     *
     * @param A1inv       the inverse of A1(the matrix part of the affine linear map L1)
     *                    (n-v1 x n-v1 matrix) (in bytes)
     * @param b1          translation vector, part of the linear affine map L1 (in
     *                    bytes)
     * @param A2inv       the inverse of A2(the matrix part of the affine linear map L2)
 *                    (n x n matrix) (in bytes)
     * @param b2          translation vector, part of the linear affine map L1 (in
*                    bytes)
     * @param vi          number of Vinegar-variables per layer (in bytes)
     * @param coeff_alpha alpha-coefficients of the polynomials in this layer (in bytes)
     * @param coeff_beta  beta-coefficients of the polynomials in this layer (in bytes)
     * @param coeff_gamma gamma-coefficients of the polynomials in this layer (in bytes)
     * @param coeff_eta   eta-coefficients of the polynomials in this layer (in bytes)
     */
    public RainbowPrivateKeyParameters(byte[][] A1inv, byte[] b1,
                                       byte[][] A2inv, byte[] b2, byte[] vi, byte[][][][] coeff_alpha,
                                       byte[][][][] coeff_beta, byte[][][] coeff_gamma, byte[][] coeff_eta, RainbowParameters params)
    {

        super(true, params);


        // map L1
        this.A1inv = RainbowUtil.convertArray(A1inv);
        this.b1 = RainbowUtil.convertArray(b1);

        // map L2
        this.A2inv = RainbowUtil.convertArray(A2inv);
        this.b2 = RainbowUtil.convertArray(b2);

        // map F
        this.vi = RainbowUtil.convertArraytoInt(vi);
        // create the (vn - 1) layers of F
        int numOfLayers = vi.length - 1;
        this.layers = new Layer[numOfLayers];
        for (int i = 0; i < numOfLayers; i++)
        {
            Layer l = new Layer(i, vi[i], vi[i + 1], coeff_alpha[i],
                coeff_beta[i], coeff_gamma[i], coeff_eta[i]);
            this.layers[i] = l;

        }
    }



    /*
      * invertible affine linear map L1
      */
    // the inverse of A1, (n-v1 x n-v1 matrix)
    private short[][] A1inv;

    // translation vector of L1
    private short[] b1;

    /*
      * invertible affine linear map L2
      */
    // the inverse of A2, (n x n matrix)
    private short[][] A2inv;

    // translation vector of L2
    private short[] b2;

    /*
      * components of F
      */
    // the number of Vinegar-variables per layer.
    private int[] vi;

    // contains the polynomials with their coefficients of private map F
    private Layer[] layers;


    /**
     * @return name of the algorithm - "Rainbow"
     */
    public final String getAlgorithm()
    {
        return "Rainbow";
    }

    /**
     * Getter for the translation part of the private quadratic map L1.
     *
     * @return b1 the translation part of L1
     */
    public short[] getb1()
    {
        return this.b1;
    }

    /**
     * Getter for the inverse matrix of A1.
     *
     * @return the A1inv inverse
     */
    public short[][] getA1inv()
    {
        return this.A1inv;
    }

    /**
     * Getter for the translation part of the private quadratic map L2.
     *
     * @return b2 the translation part of L2
     */
    public short[] getb2()
    {
        return this.b2;
    }

    /**
     * Getter for the inverse matrix of A2
     *
     * @return the A2inv
     */
    public short[][] getA2inv()
    {
        return this.A2inv;
    }

    /**
     * Returns the layers contained in the private key
     *
     * @return layers
     */
    public Layer[] getLayers()
    {
        return this.layers;
    }

    /**
     * /** Returns the array of vi-s
     *
     * @return the vi
     */
    public int[] getVi()
    {
        return vi;
    }

}
