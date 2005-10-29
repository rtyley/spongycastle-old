package org.bouncycastle.util.encoders.test;

import org.bouncycastle.util.encoders.Base64Encoder;

public class Base64Test extends AbstractCoderTest
{
    public Base64Test(
        String    name)
    {
        super(name);
    }
    
    protected void setUp()
    {
        super.setUp();
        enc = new Base64Encoder();
    }

    protected char paddingChar()
    {
        return '=';
    }

    protected boolean isEncodedChar(char c)
    {
        if (Character.isLetterOrDigit(c))
        {
            return true;
        }
        else if (c == '+')
        {
            return true;
        }
        else if (c == '/')
        {
            return true;
        }
        return false;
    }

}
