package org.spongycastle.cavp.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.spongycastle.util.encoders.Hex;

import static org.spongycastle.crypto.generators.DSAParametersGenerator.calculateGenerator_FIPS186_3_Verifiable;

public class DsaTest
{
    private String baseDir;
    private ProcessorFactoryProducer producer;

    public DsaTest(String baseDir, ProcessorFactoryProducer producer)
        throws Exception
    {
        this.baseDir = baseDir;
        this.producer = producer;
    }

    public List<String> run()
        throws Exception
    {
        List<String> errors = new ArrayList<String>();
        File dataDir = new File(baseDir);

        for (File data : dataDir.listFiles())
        {
            if (data.getName().startsWith("PQGVer"))
            {
                processPQGVer(data, null, errors);        
            }
            else
            {
                System.err.println("ignoring " + data);
            }

            if (!errors.isEmpty())
            {
                return errors;
            }
        }

        return errors;
    }

    private void processPQGVer(File f, DigestProcessorFactory processorFactory, List<String> errors)
        throws Exception
    {
        BufferedReader bRd = new BufferedReader(new FileReader(f));

        String line = bRd.readLine();
        while (line.startsWith("#"))
        {
            line = bRd.readLine();
        }

        String mod = bRd.readLine();

        while (bRd.readLine() != null)
        {
            String line1 = bRd.readLine();
            if (line1 == null || line1.startsWith("["))
            {
                mod = line;
                continue;
            }
            
            BigInteger P = new BigInteger(1, (byte[])parseLine(line1).getValue());
            BigInteger Q = new BigInteger(1, (byte[])parseLine(bRd).getValue());
            BigInteger G = new BigInteger(1, (byte[])parseLine(bRd).getValue());
            byte[] seed = (byte[])parseLine(bRd).getValue();
            Integer c = (Integer)parseLine(bRd).getValue();
            byte[] H = (byte[])parseLine(bRd).getValue();
            String result = (String)parseLine(bRd).getValue();

            System.err.println("P " + P.bitLength());
        }

        bRd.close();
    }

    private Entry parseLine(BufferedReader bRd)
        throws IOException
    {
        return parseLine(bRd.readLine());
    }

    private Entry parseLine(String line)
        throws IOException
    {
        if (line == null || line.isEmpty())
        {
            return null;
        }

        String[] vals = line.split(" = ");

        return new Entry(vals[0], vals[1]);
    }

    public String getName()
    {
        return "SHA";
    }

    static class Entry
    {
        private final String name;
        private final String value;

        Entry(String name, String value)
        {
           this.name = name;
            this.value = value;
        }

        String getName()
        {
            return name;
        }

        Object getValue()
        {
            if (name.equals("c"))
            {
                return new Integer(value);
            }
            else if (name.equals("Result"))
            {
                return value;
            }
            else
            {
                return Hex.decode(value);
            }
        }
    }
}