package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

import java.math.BigInteger;

public class DHParameters
    implements CipherParameters
{
    private BigInteger              g;
    private BigInteger              p;
    private BigInteger              q;
    private BigInteger              j;
    private int                     l;
    private DHValidationParameters  validation;

    public DHParameters(
        BigInteger  p,
        BigInteger  g)
    {
        this.g = g;
        this.p = p;
    }

    public DHParameters(
        BigInteger  p,
        BigInteger  g,
        BigInteger  q)
    {
        this.g = g;
        this.p = p;
        this.q = q;
    }

    public DHParameters(
        BigInteger  p,
        BigInteger  g,
        BigInteger  q,
        int         l)
    {
        this.g = g;
        this.p = p;
        this.q = q;
        this.l = l;
    }   

    public DHParameters(
        BigInteger              p,
        BigInteger              g,
        BigInteger              q,
        BigInteger              j,
        DHValidationParameters  validation)
    {
        this(p, g, q, 0, j, validation);
    }

    public DHParameters(
        BigInteger              p,
        BigInteger              g,
        BigInteger              q,
        int                     l,
        BigInteger              j,
        DHValidationParameters  validation)
    {
        this.g = g;
        this.p = p;
        this.q = q;
        this.l = l;
        this.j = j;
        this.validation = validation;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getG()
    {
        return g;
    }

    public BigInteger getQ()
    {
        return q;
    }

    /**
     * Return the subgroup factor J.
     *
     * @return subgroup factor
     */
    public BigInteger getJ()
    {
        return j;
    }

    /**
     * Return the private value length in bits - if set, zero otherwise (use bitLength(P) - 1).
     *
     * @return the private value length in bits, zero otherwise.
     */
    public int getL()
    {
        return l;
    }

    public DHValidationParameters getValidationParameters()
    {
        return validation;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof DHParameters))
        {
            return false;
        }

        DHParameters    pm = (DHParameters)obj;

        if (this.getQ() != null)
        {
            if (!this.getQ().equals(pm.getQ()))
            {
                return false;
            }
        }
        else
        {
            if (pm.getQ() != null)
            {
                return false;
            }
        }

        if (this.getJ() != null)
        {
            if (!this.getJ().equals(pm.getJ()))
            {
                return false;
            }
        }
        else
        {
            if (pm.getJ() != null)
            {
                return false;
            }
        }

        return (l == pm.getL()) && pm.getP().equals(p) && pm.getG().equals(g);
    }
    
    public int hashCode()
    {
        return getL() ^ getP().hashCode() ^ getG().hashCode() ^ (getQ() != null ? getQ().hashCode() : 0);
    }
}
