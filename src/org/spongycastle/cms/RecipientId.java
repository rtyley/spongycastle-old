package org.spongycastle.cms;

import java.security.cert.X509CertSelector;

import org.spongycastle.util.Selector;

public abstract class RecipientId
    extends X509CertSelector
    implements Selector
{
    public static final int keyTrans = 0;
    public static final int kek = 1;
    public static final int keyAgree = 2;
    public static final int password = 3;

    private final int type;

    protected RecipientId(int type)
    {
        this.type = type;
    }

    /**
     * Return the type code for this recipient ID.
     *
     * @return one of keyTrans, kek, keyAgree, password
     */
    public int getType()
    {
        return type;
    }
}
