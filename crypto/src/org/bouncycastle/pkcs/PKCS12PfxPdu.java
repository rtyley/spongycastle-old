package org.bouncycastle.pkcs;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * A holding class for the PKCS12 Pfx structure.
 */
public class PKCS12PfxPdu
{
    private Pfx pfx;

    public PKCS12PfxPdu(Pfx pfx)
    {
        this.pfx = pfx;
    }

    /**
     * Return whether or not there is MAC attached to this file.
     *
     * @return true if there is, false otherwise.
     */
    public boolean hasMac()
    {
        return pfx.getMacData() != null;
    }

    /**
     * Verify the MacData attached to the PFX is consistent with what is expected.
     *
     * @param macCalcProviderBuilder provider builder for the calculator for the MAC
     * @param password password to use
     * @return true if mac data is valid, false otherwise.
     * @throws PKCSException if there is a problem evaluating the MAC.
     * @throws IllegalStateException if no MAC is actually present
     */
    public boolean isMacValid(PKCS12MacCalculatorBuilderProvider macCalcProviderBuilder, char[] password)
        throws PKCSException
    {
        if (hasMac())
        {
            MacData pfxmData = pfx.getMacData();
            MacDataGenerator mdGen = new MacDataGenerator(macCalcProviderBuilder.get(new AlgorithmIdentifier(pfxmData.getMac().getAlgorithmId().getAlgorithm(), new PKCS12PBEParams(pfxmData.getSalt(), pfxmData.getIterationCount().intValue()))));

            try
            {


                MacData mData = mdGen.build(
                    password,
                    ASN1OctetString.getInstance(pfx.getAuthSafe().getContent()).getOctets());

                return Arrays.constantTimeAreEqual(mData.getEncoded(), pfx.getMacData().getEncoded());
            }
            catch (IOException e)
            {
                throw new PKCSException("unable to process AuthSafe: " + e.getMessage());
            }
        }

        throw new IllegalStateException("no MAC present on PFX");
    }

    /**
     * Return the underlying ASN.1 object.
     *
     * @return a Pfx object.
     */
    public Pfx toASN1Structure()
    {
        return pfx;
    }
}
