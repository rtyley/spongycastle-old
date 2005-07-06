package org.bouncycastle.asn1;

import java.io.*;
import java.util.*;
import java.io.*;

/**
 * UTC time object.
 */
public class DERUTCTime extends DERObject
{
    String time;

    /**
     * The correct format for this is YYMMDDHHMMSSZ (it used to be that seconds
     * were never encoded. When you're creating one of these objects from
     * scratch, that's what you want to use, otherwise we'll try to deal with
     * whatever gets read from the input stream... (this is why the input format
     * is different from the getTime() method output).
     * <p>
     * 
     * @param time
     *            the time string.
     */
    public DERUTCTime(String time)
    {
        this.time = time;
    }

    DERUTCTime(byte[] bytes)
    {
        //
        // explicitly convert to characters
        //
        char[] dateC = new char[bytes.length];

        for (int i = 0; i != dateC.length; i++)
        {
            dateC[i] = (char)(bytes[i] & 0xff);
        }

        this.time = new String(dateC);
    }

    /**
     * return the time - always in the form of YYMMDDhhmmssGMT(+hh:mm|-hh:mm).
     * <p>
     * Normally in a certificate we would expect "Z" rather than "GMT", however
     * adding the "GMT" means we can just use:
     * 
     * <pre>
     * dateF = new SimpleDateFormat(&quot;yyMMddHHmmssz&quot;);
     * </pre>
     * 
     * To read in the time and get a date which is compatible with our local
     * time zone.
     */
    public String getTime()
    {
        //
        // standardise the format.
        //
        if (time.length() == 11)
        {
            return time.substring(0, 10) + "00GMT+00:00";
        }
        else if (time.length() == 13)
        {
            return time.substring(0, 12) + "GMT+00:00";
        }
        else if (time.length() == 17)
        {
            return time.substring(0, 12) + "GMT" + time.substring(12, 15) + ":"
                    + time.substring(15, 17);
        }

        return time;
    }

    /**
     * return the time as an adjusted date with a 4 digit year. This goes in the
     * range of 1950 - 2049.
     */
    public String getAdjustedTime()
    {
        String d = this.getTime();

        if (d.charAt(0) < '5')
        {
            return "20" + d;
        }
        else
        {
            return "19" + d;
        }
    }

    void encode(DEROutputStream out) throws IOException
    {
        out.writeEncoded(UTC_TIME, time.getBytes());
    }

    public boolean equals(Object o)
    {
        if ((o == null) || !(o instanceof DERUTCTime))
        {
            return false;
        }

        return time.equals(((DERUTCTime)o).time);
    }

    public int hashCode()
    {
        return time.hashCode();
    }

}
