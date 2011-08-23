package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.util.BCKeyFactory;

/**
 * For some reason the class path project thinks that such a KeyFactory will exist.
 */
public class X509
{
    private static final Map keyFactories = new HashMap();

    static void registerKeyFactory(ASN1ObjectIdentifier id, BCKeyFactory factory)
    {
        keyFactories.put(id, factory);
    }

    public static BCKeyFactory getKeyFactory(ASN1ObjectIdentifier algorithm)
    {
        return (BCKeyFactory)keyFactories.get(algorithm);
    }

    public static class Mappings
        extends HashMap
    {
        public Mappings()
        {
            put("KeyFactory.X.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory");

            //
            // certificate factories.
            //
            put("CertificateFactory.X.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory");
            put("Alg.Alias.CertificateFactory.X509", "X.509");
        }
    }
}
