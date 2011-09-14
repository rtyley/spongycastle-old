package org.bouncycastle.jce.interfaces;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

/**
 * Implemented by the BC provider. This allows setting of hidden parameters,
 * such as the ImplicitCA parameters from X.962, if used.
 */
public interface ConfigurableProvider
{
    static final String      THREAD_LOCAL_EC_IMPLICITLY_CA = "threadLocalEcImplicitlyCa";   
    static final String      EC_IMPLICITLY_CA = "ecImplicitlyCa";

    void setParameter(String parameterName, Object parameter);

    void addAlgorithm(String key, String value);

    boolean hasAlgorithm(String type, String name);

    void addKeyInfoConverter(ASN1ObjectIdentifier oid, AsymmetricKeyInfoConverter keyInfoConverter);

    AsymmetricKeyInfoConverter getConverter(ASN1ObjectIdentifier oid);
}
