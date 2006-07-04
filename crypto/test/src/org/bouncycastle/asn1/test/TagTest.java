package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;


/**
 * X.690 test example
 */
public class TagTest
    extends SimpleTest
{
    byte[] longTagged = Base64.decode(
                  "ZSRzIp8gEEZFRENCQTk4NzY1NDMyMTCfIQwyMDA2MDQwMTEyMzSUCCAFERVz"
                + "A4kCAHEXGBkalAggBRcYGRqUCCAFZS6QAkRFkQlURUNITklLRVKSBQECAwQF"
                + "kxAREhMUFRYXGBkalAggBREVcwOJAgBxFxgZGpQIIAUXGBkalAggBWUukAJE"
                + "RZEJVEVDSE5JS0VSkgUBAgMEBZMQERITFBUWFxgZGpQIIAURFXMDiQIAcRcY"
                + "GRqUCCAFFxgZGpQIIAVlLpACREWRCVRFQ0hOSUtFUpIFAQIDBAWTEBESExQV"
                + "FhcYGRqUCCAFERVzA4kCAHEXGBkalAggBRcYGRqUCCAFFxgZGpQIIAUXGBka"
                + "lAg=");

    public String getName()
    {
        return "Tag";
    }
    
    public void performTest()
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(longTagged);

        DERApplicationSpecific app = (DERApplicationSpecific)aIn.readObject();
        
        aIn = new ASN1InputStream(app.getContents());
        
        app = (DERApplicationSpecific)aIn.readObject();
        
        aIn = new ASN1InputStream(app.getContents());
        
        ASN1TaggedObject tagged = (ASN1TaggedObject)aIn.readObject();
        
        if (tagged.getTagNo() != 32)
        {
            fail("unexpected tag value found - not 32");
        }
        
        tagged = (ASN1TaggedObject)aIn.readObject();
        
        if (tagged.getTagNo() != 33)
        {
            fail("unexpected tag value found - not 32");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new TagTest());
    }
}
