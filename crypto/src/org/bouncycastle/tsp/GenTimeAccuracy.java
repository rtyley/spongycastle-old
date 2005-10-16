
package org.bouncycastle.tsp;

import java.text.*;
import org.bouncycastle.asn1.tsp.Accuracy;

public class GenTimeAccuracy
{
    private Accuracy accuracy;

    // ==============================================================================

    public GenTimeAccuracy(Accuracy accuracy)
    {
        this.accuracy = accuracy;
    }

    // ==============================================================================

    public int getSeconds()
    {
        try
        {
            return accuracy.getSeconds().getValue().intValue();
        }
        catch (Exception e)
        {
            return 0;
        }
    }

    public int getMillis()
    {
        try
        {
            return accuracy.getMillis().getValue().intValue();
        }
        catch (Exception e)
        {
            return 0;
        }
    }

    public int getMicros()
    {
        try
        {
            return accuracy.getMicros().getValue().intValue();
        }
        catch (Exception e)
        {
            return 0;
        }
    }

    // ------------------------------------------------------------------------------

    /*
     * If the millis or micros are greater than 1000, the result will be quite
     * wrong, but for testing purposes this is good enough.
     */

    public String toString()
    {
        DecimalFormat formatter = new DecimalFormat("000"); // three integer
                                                            // digits
        return getSeconds() + "'" + formatter.format(getMillis())
                + formatter.format(getMicros());
    }

    //  ------------------------------------------------------------------------------

}
