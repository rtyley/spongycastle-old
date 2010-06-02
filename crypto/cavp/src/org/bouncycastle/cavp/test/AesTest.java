package org.bouncycastle.cavp.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cavp.jce.JceCryptoProcessorFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class AesTest
{
    private static Set<String> ignore = new HashSet<String>();

    static
    {
        // single bit tests
        ignore.add("CFB1VarKey192e.txt");
        ignore.add("CFB1GFSbox256e.txt");
        ignore.add("CFB1VarTxt256d.txt");
        ignore.add("CFB1VarKey128d.txt");
        ignore.add("CFB1VarKey256e.txt");
        ignore.add("CFB1GFSbox192e.txt");
        ignore.add("CFB1VarKey256d.txt");
        ignore.add("CFB1VarKey128e.txt");
        ignore.add("CFB1GFSbox128e.txt");
        ignore.add("CFB1GFSbox192d.txt");
        ignore.add("CFB1KeySbox256d.txt");
        ignore.add("CFB1VarTxt128e.txt");
        ignore.add("CFB1KeySbox128e.txt");
        ignore.add("CFB1KeySbox128d.txt");
        ignore.add("CFB1GFSbox256d.txt");
        ignore.add("CFB1KeySbox256e.txt");
        ignore.add("CFB1VarTxt256e.txt");
        ignore.add("CFB1KeySbox192d.txt");
        ignore.add("CFB1KeySbox192e.txt");
        ignore.add("CFB1GFSbox128d.txt");
        ignore.add("CFB1VarTxt192d.txt");
        ignore.add("CFB1VarTxt128d.txt");
        ignore.add("CFB1VarKey192d.txt");
        ignore.add("CFB1VarTxt192e.txt");
    }

    private String baseDir;
    private ProcessorFactoryProducer producer;

    public AesTest(String baseDir, ProcessorFactoryProducer producer)
        throws Exception
    {
        this.baseDir = baseDir;
        this.producer = producer;
    }

    public List<String> run()
        throws Exception
    {
        List<String> errors = new ArrayList<String>();

        File dataDir = new File(baseDir, "KAT_AES");

        for (File data : dataDir.listFiles())
        {
            if (ignore.contains(data.getName()))
            {
                continue;
            }

            if (data.getName().startsWith("ECB"))
            {
                processFile(data, producer.createCryptoProcessorFactory("AES/ECB/NoPadding"), errors);
            }
            else if (data.getName().startsWith("CBC"))
            {
                processFileWithIv(data, producer.createCryptoProcessorFactory("AES/CBC/NoPadding"), errors);
            }
            else if (data.getName().startsWith("CFB"))
            {
                if (data.getName().startsWith("CFB8"))
                {
                    processFileWithIv(data, producer.createCryptoProcessorFactory("AES/CFB8/NoPadding"), errors);
                }
                else if (data.getName().startsWith("CFB128"))
                {
                    processFileWithIv(data, producer.createCryptoProcessorFactory("AES/CFB128/NoPadding"), errors);
                }
                else
                {
                    errors.add("ignoring " + data);
                }
            }
            else if (data.getName().startsWith("OFB"))
            {
                if (data.getName().startsWith("OFB"))
                {
                    processFileWithIv(data, new JceCryptoProcessorFactory("AES/OFB/NoPadding"), errors);
                }
                else
                {
                    errors.add("ignoring " + data);
                }
            }
            else
            {
                errors.add("ignoring " + data);
            }

            if (!errors.isEmpty())
            {
                return errors;
            }
        }

        return errors;
    }

    private void processFile(File f, CryptoProcessorFactory processorFactory, List<String> errors)
        throws Exception
    {
        BufferedReader bRd = new BufferedReader(new FileReader(f));

        String operation = bRd.readLine();

        if (operation.equals("[DECRYPT]"))
        {
            while (bRd.readLine() != null)
            {
                CryptoProcessor processor = processorFactory.getDecryptor();

                Entry counter = parseLine(bRd);
                byte[] key = (byte[])parseLine(bRd).getValue();
                byte[] cipherText = (byte[])parseLine(bRd).getValue();
                byte[] plainText = (byte[])parseLine(bRd).getValue();

                processor.init(key);

                byte[] output = processor.process(cipherText);

                if (!Arrays.areEqual(output, plainText))
                {
                    errors.add(f.getName() + ": " + counter.getValue() + " failed.");
                }
            }
        }

        bRd.close();
    }

    private void processFileWithIv(File f, CryptoProcessorFactory processorFactory, List<String> errors)
        throws Exception
    {
        BufferedReader bRd = new BufferedReader(new FileReader(f));

        String operation = bRd.readLine();
        CryptoProcessor processor;

        if (operation.equals("[DECRYPT]"))
        {
            processor = processorFactory.getDecryptor();
        }
        else
        {
            processor = processorFactory.getEncryptor();
        }

        while (bRd.readLine() != null)
        {

            Entry counter = parseLine(bRd);
            byte[] key = (byte[])parseLine(bRd).getValue();
            byte[] iv = (byte[])parseLine(bRd).getValue();
            byte[] cipherText = (byte[])parseLine(bRd).getValue();
            byte[] plainText = (byte[])parseLine(bRd).getValue();

            processor.init(key, iv);

            byte[] output = processor.process(cipherText);

            if (!Arrays.areEqual(output, plainText))
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

        String[] vals = line.split(" = ");

        return new Entry(vals[0], vals[1]);
    }

    public String getName()
    {
        return "AES";
    }

    private class Entry
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
            if (name.equals("COUNT"))
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
