package org.bouncycastle.x509;

import java.util.Collection;

public class X509CollectionStoreParameters
    implements X509StoreParameters
{
    private Collection collection;

    public X509CollectionStoreParameters(Collection collection)
    {
        this.collection = collection;
    }

    public Collection getCollection()
    {
        return collection;
    }
}
