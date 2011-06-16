package org.bouncycastle.openpgp.operator;

public class PGPSymmetricKey
{
    private Object representation;

    public PGPSymmetricKey(Object representation)
    {
        this.representation = representation;
    }

    public Object getRepresentation()
    {
        return representation;
    }
}
