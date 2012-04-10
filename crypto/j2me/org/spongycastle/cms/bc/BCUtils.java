package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;

class BCUtils
{
    public static CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier encryptionOID)
    {
        if (encryptionOID.equals(CMSAlgorithm.DES_EDE3_CBC) || encryptionOID.equals(CMSAlgorithm.DES_EDE3_WRAP))
        {
            return new DESedeKeyGenerator();
        }
        return new CipherKeyGenerator();
    }
}
