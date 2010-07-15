package org.bouncycastle.cert.crmf;

import java.security.SecureRandom;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.crmf.PKMACValue;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Strings;

public class PKMACValueGenerator
{
    private AlgorithmIdentifier owf;
    private int iterationCount;
    private AlgorithmIdentifier mac;
    private int saltLength = 20;
    private SecureRandom random;
    private PKMACValuesCalculator calculator;

    public PKMACValueGenerator(PKMACValuesCalculator calculator)
    {
        this(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), 1000, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA1, DERNull.INSTANCE), calculator);
    }

    private PKMACValueGenerator(AlgorithmIdentifier hashAlgorithm, int iterationCount, AlgorithmIdentifier macAlgorithm, PKMACValuesCalculator calculator)
    {
        if (iterationCount < 100)
        {
            throw new IllegalArgumentException("iteration count must be at least 100");
        }

        this.owf = hashAlgorithm;
        this.iterationCount = iterationCount;
        this.mac = macAlgorithm;
        this.calculator = calculator;
    }

    /**
     * Set the salt length in octets.
     *
     * @param saltLength length in octets of the salt to be generated.
     * @return the generator
     */
    public PKMACValueGenerator setSaltLength(int saltLength)
    {
        if (saltLength < 8)
        {
            throw new IllegalArgumentException("salt length must be at least 8 bytes");
        }

        this.saltLength = saltLength;

        return this;
    }

    public PKMACValueGenerator setRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public PKMACValue generate(char[] password, SubjectPublicKeyInfo keyInfo)
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

        byte[] salt = new byte[saltLength];
        byte[] pw = Strings.toUTF8ByteArray(password);

        if (random == null)
        {
            this.random = new SecureRandom();
        }
        
        random.nextBytes(salt);

        byte[] K = new byte[pw.length + salt.length];

        System.arraycopy(pw, 0, K, 0, pw.length);
        System.arraycopy(salt, 0, K, pw.length, salt.length);

        calculator.setup(owf, mac);

        int iter = iterationCount;
        do
        {
            K = calculator.calculateDigest(K);
        }
        while (iter-- > 0);

        byte[] MAC = calculator.calculateMac(K, keyInfo.getDEREncoded());

        return new PKMACValue(new PBMParameter(salt, owf, iterationCount, mac), new DERBitString(MAC));
    }

}
