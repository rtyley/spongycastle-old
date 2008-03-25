package org.bouncycastle.cms;

import java.security.Provider;
import java.security.Security;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

public class CMSContext
{
    private static Map providers = new HashMap();

    /**
     * Add a provider for local lookup.
     *
     * @param provider  provider to be added.
     */
    public static void addProvider(Provider provider)
    {
        providers.put(provider.getName(), provider);
    }

    /**
     * Remove the provider from the context.
     *
     * @param provider provider to be removed.
     */
    public static void removeProvider(Provider provider)
    {
        providers.remove(provider.getName());
    }

    static Provider getProvider(String name)
        throws NoSuchProviderException
    {
        Provider prov = (Provider)providers.get(name);

        if (prov == null)
        {
            prov = Security.getProvider(name);
        }

        if (prov == null)
        {
            throw new NoSuchProviderException("provider " + name + " not found.");
        }

        return prov;
    }
}
