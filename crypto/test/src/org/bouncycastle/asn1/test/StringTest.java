package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.util.test.SimpleTest;

/**
 * X.690 test example
 */
public class StringTest
    extends SimpleTest
{
    public String getName()
    {
        return "String";
    }

    public void performTest()
        throws IOException
    {
        DERBitString bs = new DERBitString(
            new byte[] { (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xab,(byte)0xcd,(byte)0xef });

        if (!bs.getString().equals("#0309000123456789ABCDEF"))
        {
            fail("DERBitString.getString() result incorrect");
        }

        if (!bs.toString().equals("#0309000123456789ABCDEF"))
        {
            fail("DERBitString.toString() result incorrect");
        }

        bs = new DERBitString(
            new byte[] { (byte)0xfe,(byte)0xdc,(byte)0xba,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10 });

        if (!bs.getString().equals("#030900FEDCBA9876543210"))
        {
            fail("DERBitString.getString() result incorrect");
        }

        if (!bs.toString().equals("#030900FEDCBA9876543210"))
        {
            fail("DERBitString.toString() result incorrect");
        }

        DERUniversalString us = new DERUniversalString(
            new byte[] { (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xab,(byte)0xcd,(byte)0xef });

        if (!us.getString().equals("#1C080123456789ABCDEF"))
        {
            fail("DERUniversalString.getString() result incorrect");
        }

        if (!us.toString().equals("#1C080123456789ABCDEF"))
        {
            fail("DERUniversalString.toString() result incorrect");
        }

        us = new DERUniversalString(
            new byte[] { (byte)0xfe,(byte)0xdc,(byte)0xba,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10 });

        if (!us.getString().equals("#1C08FEDCBA9876543210"))
        {
            fail("DERUniversalString.getString() result incorrect");
        }

        if (!us.toString().equals("#1C08FEDCBA9876543210"))
        {
            fail("DERUniversalString.toString() result incorrect");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new StringTest());
    }
}
