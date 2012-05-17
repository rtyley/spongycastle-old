package org.bouncycastle.util.encoders.test;

import org.bouncycastle.util.encoders.UrlBase64Encoder;

public class UrlBase64Test extends AbstractCoderTest
{
    public UrlBase64Test(
        String name)
    {
        super(name);
    }
    
    protected void setUp()
    {
        super.setUp();
        enc = new UrlBase64Encoder();
    }

    protected char paddingChar()
    {
        return '.';
    }

    protected boolean isEncodedChar(char c)
    {
        if (Character.isLetterOrDigit(c))
        {
            return true;
        }
        else if (c == '-')
        {
            return true;
        }
        else if (c == '_')
        {
            return true;
        }
        return false;
    }
}
