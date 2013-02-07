package org.bouncycastle.cavp.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cavp.test.DigestProcessor;
import org.bouncycastle.cavp.test.DigestProcessorFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.encoders.Hex;

public class ShaTest
{
    private String baseDir;
    private ProcessorFactoryProducer producer;

    public ShaTest(String baseDir, ProcessorFactoryProducer producer)
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
            String digest;

            if (data.getName().startsWith("SHA1"))
            {
                digest = "SHA1";
            }
            else if (data.getName().startsWith("SHA224"))
            {
                digest = "SHA224";
            }
            else if (data.getName().startsWith("SHA256"))
            {
                digest = "SHA256";
            }
            else if (data.getName().startsWith("SHA384"))
            {
                digest = "SHA384";
            }
            else
            {
                digest = "SHA512";
            }

            if (data.getName().indexOf("Monte") > 0)
            {
                processFileWithMonte(data, producer.createDigestProcessorFactory(digest), errors);
            }
            else
            {
                processFile(data, producer.createDigestProcessorFactory(digest), errors);
            }

            if (!errors.isEmpty())
            {
                return errors;
            }
        }

        return errors;
    }

    private void processFile(File f, DigestProcessorFactory processorFactory, List<String> errors)
        throws Exception
    {
        BufferedReader bRd = new BufferedReader(new FileReader(f));

        String line = bRd.readLine();
        while (line.startsWith("#"))
        {
            line = bRd.readLine();
        }

        String operation = bRd.readLine();

        while (bRd.readLine() != null)
        {
            DigestProcessor processor = processorFactory.getProcessor();

            Entry len = parseLine(bRd);
            if (len == null)
            {
                break;
            }
            byte[] msg = (byte[])parseLine(bRd).getValue();
            byte[] md = (byte[])parseLine(bRd).getValue();

            if (!len.getValue().equals(Integer.valueOf(0)))
            {
                processor.update(msg);
            }

            byte[] output = processor.digest();

            if (!Arrays.areEqual(output, md))
            {
                errors.add(f.getName() + ": " + len.getValue() + " failed.");
            }
        }

        bRd.close();
    }

    private void processFileWithMonte(File f, DigestProcessorFactory processorFactory, List<String> errors)
        throws Exception
    {
        BufferedReader bRd = new BufferedReader(new FileReader(f));

        String line = bRd.readLine();
        while (line.startsWith("#"))
        {
            line = bRd.readLine();
        }

        bRd.readLine();
        bRd.readLine();

        Entry seedEntry = parseLine(bRd);
        byte[] seed = (byte[])seedEntry.getValue();

        while (bRd.readLine() != null)
        {
            DigestProcessor processor = processorFactory.getProcessor();

            Entry counter = parseLine(bRd);
            if (counter == null)
            {
                break;
            }

            byte[] md = (byte[])parseLine(bRd).getValue();

            byte[] MD0 = seed;
            byte[] MD1 = seed;
            byte[] MD2 = seed;
            for (int i = 3; i < 1003; i++)
            {
                processor.update(MD0);
                processor.update(MD1);
                processor.update(MD2);
                MD0 = MD1;
                MD1 = MD2;
                MD2 = processor.digest();
            }
            seed = MD2;

            byte[] output = seed;
            
            if (!Arrays.areEqual(output, md))
            {
                errors.add(f.getName() + ": " + counter.getValue() + " failed.");
            }
        }

        bRd.close();
    }

    private Entry parseLine(BufferedReader bRd)
        throws IOException
    {
        String line = bRd.readLine();

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
            if (name.equals("Len") || name.equals("COUNT"))
            {
                return Integer.valueOf(value);
            }
            else
            {
                return Hex.decode(value);
            }
        }
    }
}