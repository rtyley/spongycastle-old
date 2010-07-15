package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class PKMACValueVerifier
{
    private final PKMACValuesCalculator calculator;

    public PKMACValueVerifier(PKMACValuesCalculator calculator)
    {
        this.calculator = calculator;
    }

    public boolean verify(PKMACValue value, char[] password, SubjectPublicKeyInfo keyInfo)
        throws CRMFException
    {
        // From RFC 4211
        //
        //   1.  Generate a random salt value S
        //
        //   2.  Append the salt to the pw.  K = pw || salt.
        //
        //   3.  Hash the value of K.  K = HASH(K)
        //
        //   4.  If Iter is greater than zero.  Iter = Iter - 1.  Goto step 3.
        //
        //   5.  Compute an HMAC as documented in [HMAC].
        //
        //       MAC = HASH( K XOR opad, HASH( K XOR ipad, data) )
        //
        //       Where opad and ipad are defined in [HMAC].

        PBMParameter param = PBMParameter.getInstance(value.getAlgId().getParameters());

        byte[] salt = param.getSalt().getOctets();

        byte[] pw = Strings.toUTF8ByteArray(password);

        byte[] K = new byte[pw.length + salt.length];

        System.arraycopy(pw, 0, K, 0, pw.length);
        System.arraycopy(salt, 0, K, pw.length, salt.length);

        calculator.setup(param.getOwf(), param.getMac());

        int iter = param.getIterationCount().getValue().intValue();
        do
        {
            K = calculator.calculateDigest(K);
        }
        while (iter-- > 0);

        byte[] MAC = calculator.calculateMac(K, keyInfo.getDEREncoded());

        return Arrays.areEqual(MAC, value.getValue().getBytes());
    }

}