package org.bouncycastle.util.encoders.test;

import org.bouncycastle.util.encoders.HexEncoder;

public class HexTest extends AbstractCoderTest
{
    public HexTest(
        String    name)
    {
        super(name);
    }
    
    protected void setUp()
    {
        super.setUp();
        enc = new HexEncoder();
    }

    protected char paddingChar()
    {
        return 0;
    }

    protected boolean isEncodedChar(char c)
    {
        if ('A' <= c && c <= 'F')
        {
            return true;
        } 
        if ('a' <= c && c <= 'f')
        {
            return true;
        } 
        if ('0' <= c && c <= '9')
        {
            return true;
        } 
        return false;
    }

}
