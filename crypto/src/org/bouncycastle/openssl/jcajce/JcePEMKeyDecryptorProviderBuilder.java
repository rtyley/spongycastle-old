package org.bouncycastle.openssl.jcajce;

import java.security.Provider;

import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.JcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyDecryptor;
import org.bouncycastle.openssl.PEMKeyDecryptorProvider;
import org.bouncycastle.openssl.PasswordException;

public class JcePEMKeyDecryptorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcePEMKeyDecryptorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePEMKeyDecryptorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public PEMKeyDecryptorProvider  build(final char[] password)
    {
        return new PEMKeyDecryptorProvider()
        {
            public PEMKeyDecryptor get(final String dekAlgName)
            {
                return new PEMKeyDecryptor()
                {
                    public byte[] recoverKeyData(byte[] keyBytes, byte[] iv)
                        throws PEMException
                    {
                        if (password == null)
                        {
                            throw new PasswordException("Password is null, but a password is required");
                        }

                        return PEMUtilities.crypt(false, helper, keyBytes, password, dekAlgName, iv);
                    }
                };
            }
        };
    }
}
