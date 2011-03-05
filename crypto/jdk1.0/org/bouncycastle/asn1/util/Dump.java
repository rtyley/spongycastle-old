package org.spongycastle.asn1.util;

import java.io.EOFException;
import java.io.FileInputStream;

import org.spongycastle.asn1.BERInputStream;

public class Dump
{
    public static void main(
        String args[])
        throws Exception
    {
        FileInputStream fIn = new FileInputStream(args[0]);
        BERInputStream  bIn = new BERInputStream(fIn);
        Object          obj = null;

        try
        {
            while ((obj = bIn.readObject()) != null)
            {
                System.out.println(ASN1Dump.dumpAsString(obj));
            }
        }
        catch (EOFException e)
        {
            // ignore
        }
    }
}
