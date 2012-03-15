package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.pkcs.SafeBag;

public class PKCS12SafeBag
{
    private SafeBag safeBag;

    public PKCS12SafeBag(SafeBag safeBag)
    {
        this.safeBag = safeBag;
    }

    /**
     * Return the underlying ASN.1 structure for this safe bag.
     *
     * @return a SafeBag
     */
    public SafeBag toASN1Structure()
    {
        return safeBag;
    }
}
