package org.spongycastle.asn1.util;

import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;

/**
 * @deprecated use ASN1Dump.
 */
public class DERDump
    extends ASN1Dump
{
    /**
     * dump out a DER object as a formatted string
     *
     * @param obj the DERObject to be dumped out.
     */
    public static String dumpAsString(
        DERObject   obj)
    {
        return _dumpAsString("", obj);
    }

    /**
     * dump out a DER object as a formatted string
     *
     * @param obj the DERObject to be dumped out.
     */
    public static String dumpAsString(
        DEREncodable   obj)
    {
        return _dumpAsString("", obj.getDERObject());
    }
}
