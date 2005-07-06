package org.bouncycastle.jce.provider.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new FIPSDESTest(),
        new DESedeTest(),
        new AESTest(),
        new AESSICTest(),
        new GOST28147Test(),
        new PBETest(),
        new BlockCipherTest(),
        new MacTest(),
        new HMacTest(),
        new SealedTest(),
        new RSATest(),
        new DHTest(),
        new DSATest(),
        new GOST3410Test(),
        new ElGamalTest(),
        new ECIESTest(),
        new SigTest(),
        new AttrCertTest(),
        new CertTest(),
        new PKCS10CertRequestTest(),
        new PKCS7SignedDataTest(),
        new EncryptedPrivateKeyInfoTest(),
        new KeyStoreTest(),
        new PKCS12StoreTest(),
        new DigestTest(),
        new PSSTest(),
        new WrapTest(),
        new DoFinalTest(),
        new CipherStreamTest(),
        new NamedCurveTest(),
        new PKIXTest(),
        new NetscapeCertRequestTest(),
        new CertPathTest(),
        new CertStoreTest(),
        new CertPathValidatorTest(),
        new CertPathBuilderTest(),
        new NISTCertPathTest()
    };

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            
            if (((SimpleTestResult)result).getException() != null)
            {
                ((SimpleTestResult)result).getException().printStackTrace();
            }
            
            System.out.println(result);
        }
    }
}

