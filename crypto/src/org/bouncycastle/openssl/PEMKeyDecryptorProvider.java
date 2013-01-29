package org.bouncycastle.openssl;

import org.bouncycastle.operator.OperatorCreationException;

public interface PEMKeyDecryptorProvider
{
    PEMKeyDecryptor get(String dekAlgName)
        throws OperatorCreationException;
}
