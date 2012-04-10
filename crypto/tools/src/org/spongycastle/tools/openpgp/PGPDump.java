package org.bouncycastle.tools.openpgp;

import java.io.File;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tools.openpgp.dump.PGPDumpEngine;
import org.bouncycastle.tools.openpgp.util.PGPCmdLineArgProcessor;
import org.bouncycastle.tools.openpgp.util.PGPParams;

/**
 * A simple packet walker that will dump the contents of the OpenPGP Message.
 * It will process the Message to the best of its ability, depending on the
 * parameters provided to the program.
 * 
 * For example, if the SecretKeyRing and passphrase are not provided, then 
 * any contents of an Encrypted Message will be opaque and not processed.
 * 
 */
public class PGPDump
{
    private static final String PGP_DEFAULT_PUBLIC_RING = "pubring.gpg";
    private static final String PGP_DEFAULT_SECRET_RING = "secring.gpg";

    public static void main(String[] argv)
    {
        String usage = "usage:  PGPDump "
                + "[ -skr <file> ] [ -pkr <file> ] [ -K <keyring dir> ] [ -P <passphrase> ]"
                + "[ -pbe <passphrase> ] fileName";

        Security.addProvider(new BouncyCastleProvider());

        PGPDump cmdLineProcessor = new PGPDump();
        PGPParams params = cmdLineProcessor.processArguments(argv);
        if (params.isError())
        {
            System.out.println(usage);
            System.out.println("Error details - ");
            System.out.println(params.getErrors());
            System.exit(1);
        }

        PGPDumpEngine engine = new PGPDumpEngine(params);
        
        engine.process();

    }

    public PGPParams processArguments(String[] argv)
    {
        PGPCmdLineArgProcessor cmdLine = new PGPCmdLineArgProcessor();
        PGPParams rv = cmdLine.processArguments(argv);

        if (rv.getInputFile() == null)
        {
            rv.addError("Input file must be specified");
        }
        
        return rv;
    }
    
    private void processPubRing(String fileName, PGPParams rv)
    {
        File file = new File(fileName);
        if (!file.exists())
        {
            rv.addError("Public Key Ring file does not exist [" + fileName + "]");
        }
        else
        {
            rv.setPublicKeyRingFile(file);
        }
    }

    private void processSecRing(String fileName, PGPParams rv)
    {
        File file = new File(fileName);
        if (!file.exists())
        {
            rv.addError("Secret Key Ring file does not exist [" + fileName + "]");
        }
        else
        {
            rv.setSecretKeyRingFile(new File(fileName));
        }
    }

    private boolean checkDirectory(String keyRingDir)
    {
        File dir = new File(keyRingDir);
        if (dir.exists() && dir.isDirectory())
        {
            return true;
        }
        return false;
    }    
    
}
