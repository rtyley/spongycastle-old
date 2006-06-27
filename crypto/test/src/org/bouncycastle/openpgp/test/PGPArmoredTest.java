package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class PGPArmoredTest
    implements Test
{
    byte[] sample = Base64.decode(
            "mQGiBEA83v0RBADzKVLVCnpWQxX0LCsevw/3OLs0H7MOcLBQ4wMO9sYmzGYn"
          + "xpVj+4e4PiCP7QBayWyy4lugL6Lnw7tESvq3A4v3fefcxaCTkJrryiKn4+Cg"
          + "y5rIBbrSKNtCEhVi7xjtdnDjP5kFKgHYjVOeIKn4Cz/yzPG3qz75kDknldLf"
          + "yHxp2wCgwW1vAE5EnZU4/UmY7l8kTNkMltMEAJP4/uY4zcRwLI9Q2raPqAOJ"
          + "TYLd7h+3k/BxI0gIw96niQ3KmUZDlobbWBI+VHM6H99vcttKU3BgevNf8M9G"
          + "x/AbtW3SS4De64wNSU3189XDG8vXf0vuyW/K6Pcrb8exJWY0E1zZQ1WXT0gZ"
          + "W0kH3g5ro//Tusuil9q2lVLF2ovJA/0W+57bPzi318dWeNs0tTq6Njbc/GTG"
          + "FUAVJ8Ss5v2u6h7gyJ1DB334ExF/UdqZGldp0ugkEXaSwBa2R7d3HBgaYcoP"
          + "Ck1TrovZzEY8gm7JNVy7GW6mdOZuDOHTxyADEEP2JPxh6eRcZbzhGuJuYIif"
          + "IIeLOTI5Dc4XKeV32a+bWrQidGVzdCAoVGVzdCBrZXkpIDx0ZXN0QHViaWNh"
          + "bGwuY29tPohkBBMRAgAkBQJAPN79AhsDBQkB4TOABgsJCAcDAgMVAgMDFgIB"
          + "Ah4BAheAAAoJEJh8Njfhe8KmGDcAoJWr8xgPr75y/Cp1kKn12oCCOb8zAJ4p"
          + "xSvk4K6tB2jYbdeSrmoWBZLdMLACAAC5AQ0EQDzfARAEAJeUAPvUzJJbKcc5"
          + "5Iyb13+Gfb8xBWE3HinQzhGr1v6A1aIZbRj47UPAD/tQxwz8VAwJySx82ggN"
          + "LxCk4jW9YtTL3uZqfczsJngV25GoIN10f4/j2BVqZAaX3q79a3eMiql1T0oE"
          + "AGmD7tO1LkTvWfm3VvA0+t8/6ZeRLEiIqAOHAAQNBACD0mVMlAUgd7REYy/1"
          + "mL99Zlu9XU0uKyUex99sJNrcx1aj8rIiZtWaHz6CN1XptdwpDeSYEOFZ0PSu"
          + "qH9ByM3OfjU/ya0//xdvhwYXupn6P1Kep85efMBA9jUv/DeBOzRWMFG6sC6y"
          + "k8NGG7Swea7EHKeQI40G3jgO/+xANtMyTIhPBBgRAgAPBQJAPN8BAhsMBQkB"
          + "4TOAAAoJEJh8Njfhe8KmG7kAn00mTPGJCWqmskmzgdzeky5fWd7rAKCNCp3u"
          + "ZJhfg0htdgAfIy8ppm05vLACAAA=");
    
    byte[] marker = Hex.decode("2d2d2d2d2d454e4420504750205055424c4943204b455920424c4f434b2d2d2d2d2d");
    
    private int markerCount(
        byte[] data)
    {
        int ind = 0;
        int matches = 0;
        
        while (ind < data.length)
        {
            if (data[ind] == 0x2d)
            {
                int count = 0;
                while (count < marker.length)
                {
                    if (data[ind + count] != marker[count])
                    {
                        break;
                    }
                    count++;
                }
                
                if (count == marker.length)
                {
                    matches++;
                }
                
                ind += count;
            }
            else
            {
                ind++;
            }
        }
        
        return matches;
    }
    
    public TestResult perform()
    {
        try
        {
            //
            // test immediate close
            //
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ArmoredOutputStream aos = new ArmoredOutputStream(baos);
            
            aos.close();

            byte[] data = baos.toByteArray();

            if (data.length != 0)
            {
                return new SimpleTestResult(false, "No data should have been written");
            }
            
            //
            // multiple close
            //
            baos = new ByteArrayOutputStream();
            aos = new ArmoredOutputStream(baos);
            
            aos.write(sample);
            
            aos.close();
            
            aos.close();

            int mc = markerCount(baos.toByteArray());

            if (mc < 1)
            {
                return new SimpleTestResult(false, "No end marker found");
            }

            if (mc > 1)
            {
                return new SimpleTestResult(false, "More than one end marker found");
            }
            
            return new SimpleTestResult(true, getName() + ": Okay");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString(), e);
        }
    }

    public String getName()
    {
        return "PGPArmoredTest";
    }

    public static void main(
        String[]    args)
    {
        Test            test = new PGPArmoredTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
