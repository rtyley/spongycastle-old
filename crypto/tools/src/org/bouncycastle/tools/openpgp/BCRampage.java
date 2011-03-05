package org.spongycastle.tools.openpgp;

import java.security.Security;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.tools.openpgp.rampage.PGPRampageEngine;
import org.spongycastle.tools.openpgp.util.PGPCmdLineArgProcessor;
import org.spongycastle.tools.openpgp.util.PGPParams;

/**
 * A general tool for manipulating PGP messages.
 */
public class BCRampage
{
    private boolean             _verbose                = true;

    public PGPParams processArguments(String[] args)
    {
        PGPCmdLineArgProcessor cmdLine = new PGPCmdLineArgProcessor();
        PGPParams rv = cmdLine.processArguments(args);

        if (rv.getInputFile() == null)
        {
            rv.addError("Input file must be specified");
        }
        
        return rv;
    }

    public static void main(String[] args)
    {
        String usage = "usage:  BCRampage [ -e[a] | -d | -s | -v  ] "
                + "[ -skr <file> ] [ -pkr <file> ] [ -K <keyring dir> ] [ -P <passphrase> ]"
                + "[ -R <recipient> ] [ -pbe <passphrase> ] [ -mdc ] fileName";

        Security.addProvider(new BouncyCastleProvider());

        BCRampage cmdLineProcessor = new BCRampage();
        PGPParams params = cmdLineProcessor.processArguments(args);

        if (params.isError())
        {
            System.out.println(usage);
            System.out.println("Error details - ");
            System.out.println(params.getErrors());
            System.exit(1);
        }

        PGPRampageEngine engine = new PGPRampageEngine(params);
        engine.process();

    }

}
