package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.DERBitString;

/**
 * <pre>
 * PKIFailureInfo ::= BIT STRING {
 * badAlg               (0),
 *   -- unrecognized or unsupported Algorithm Identifier
 * badRequest           (2),
 *   -- transaction not permitted or supported
 * badDataFormat        (5),
 *   -- the data submitted has the wrong format
 * timeNotAvailable    (14),
 *   -- the TSA's time source is not available
 * unacceptedPolicy    (15),
 *   -- the requested TSA policy is not supported by the TSA
 * unacceptedExtension (16),
 *   -- the requested extension is not supported by the TSA
 *  addInfoNotAvailable (17)
 *    -- the additional information requested could not be understood
 *    -- or is not available
 *  systemFailure       (25)
 *    -- the request cannot be handled due to system failure  }
 * </pre>
 */
public class PKIFailureInfo
    extends DERBitString
{
    public static final int BAD_ALG                   = (1 << 7); // unrecognized or unsupported Algorithm Identifier
    public static final int BAD_REQUEST               = (1 << 6); // transaction not permitted or supported
    public static final int BAD_DATA_FORMAT           = (1 << 3); // the data submitted has the wrong format
    public static final int TIME_NOT_AVAILABLE        = (1 << 9); // the TSA's time source is not available
    public static final int UNACCEPTED_POLICY         = (1 << 8); // the requested TSA policy is not supported by the TSA
    public static final int UNACCEPTED_EXTENSION      = (1 << 23); //the requested extension is not supported by the TSA
    public static final int ADD_INFO_NOT_AVAILABLE    = (1 << 16); //the additional information requested could not be understood or is not available
    public static final int SYSTEM_FAILURE            = (1 << 30); //the request cannot be handled due to system failure

    /**
     * Basic constructor.
     */
    public PKIFailureInfo(
        int info)
    {
        super(getBytes(info), getPadBits(info));
    }

    public PKIFailureInfo(
        DERBitString info)
    {
        super(info.getBytes(), info.getPadBits());
    }
    
    public String toString()
    {
        return "PKIFailureInfo: 0x" + Integer.toHexString(this.intValue());
    }
}
