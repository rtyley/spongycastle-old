package org.bouncycastle.asn1.test;

import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new EqualsAndHashCodeTest(),
        new TagTest(),
        new SetTest(),
        new DERUTF8StringTest(),
        new CertificateTest(),
        new GenerationTest(),
        new CMSTest(),
        new OCSPTest(),
        new OIDTest(),
        new PKCS10Test(),
        new PKCS12Test(),
        new X509NameTest(),
        new GeneralizedTimeTest(),
        new BitStringTest(),
        new MiscTest(),
        new SMIMETest(),
        new X9Test(),
        new MonetaryValueUnitTest(),
        new BiometricDataUnitTest(),
        new Iso4217CurrencyCodeUnitTest(),
        new SemanticsInformationUnitTest(),
        new QCStatementUnitTest(),
        new TypeOfBiometricDataUnitTest(),
        new SignerLocationUnitTest(),
        new CommitmentTypeQualifierUnitTest(),
        new CommitmentTypeIndicationUnitTest(),
        new EncryptedPrivateKeyInfoTest(),
        new DataGroupHashUnitTest(),
        new LDSSecurityObjectUnitTest(),
        new AttributeTableUnitTest(),
        new ReasonFlagsTest(),
        new NetscapeCertTypeTest(),
        new PKIFailureInfoTest(),
        new KeyUsageTest()
    };

    public static void main(
        String[]    args)
    {
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

