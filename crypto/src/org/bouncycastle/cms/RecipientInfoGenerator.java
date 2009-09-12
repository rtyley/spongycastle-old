package org.bouncycastle.cms;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.bouncycastle.asn1.cms.RecipientInfo;

interface RecipientInfoGenerator
{
    /**
     * Generate a RecipientInfo object for the given key.
     * @param key
     * @param random
     * @param prov
     * @return
     * @throws GeneralSecurityException
     */
    RecipientInfo generate(SecretKey key, SecureRandom random,
        Provider prov) throws GeneralSecurityException;
}
