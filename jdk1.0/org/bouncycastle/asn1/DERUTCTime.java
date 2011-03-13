package org.spongycastle.asn1;

import java.io.IOException;

/**
 * UTC time object.
 */
public class DERUTCTime
    extends DERObject
{
    String      time;

    /**
     * @param data the octets making up the time.
     */
    public DERUTCTime(
        String  time)
    {
        this.time = time;
    }

    DERUTCTime(
        byte[]  bytes)
    {
        //
        // explicitly convert to characters
        //
        char[]  dateC = new char[bytes.length];

        for (int i = 0; i != dateC.length; i++)
        {
            dateC[i] = (char)(bytes[i] & 0xff);
        }

        this.time = new String(dateC);
    }

    /**
     * return the time - always in the form of 
     *  YYMMDDhhmmss[Z|+hh'mm'|-hh'mm']
     */
    public String getTime()
    {
        //
        // standardise the format.
        //
        if (time.length() == 11)
        {
            return time.substring(0, 10) + "00Z";
        }
        else if (time.length() == 17)
        {
            return time.substring(0, 10) + "00" + time.substring(10);
        }

        return time;
    }

    /**
     * return the time as an adjusted date with a 4 digit year. This goes
     * in the range of 1950 - 2049.
     */
    public String getAdjustedTime()
    {
        String   d = this.getTime();

        if (d.charAt(0) < '5')
        {
            return "20" + d;
        }
        else
        {
            return "19" + d;
        }
    }

    void encode(
        DEROutputStream  out)
        throws IOException
    {
        byte[]  bytes = new byte[time.length()];

        time.getBytes(0, time.length(), bytes, 0);

        out.writeEncoded(UTC_TIME, bytes);
    }
    
    public boolean equals(
        Object  o)
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
