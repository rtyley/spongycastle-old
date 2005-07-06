package org.bouncycastle.tools.openpgp.rampage;

import org.bouncycastle.tools.openpgp.BCRampage;
import org.bouncycastle.tools.openpgp.util.PGPParams;

import junit.framework.TestCase;

/*
 * NOTE:  This test class _will not work_ in your environment unless you have
 * the same files in the same places that I do.  This is purely for my purposes
 * to avoid having to run lots of command line programs to make it all work.
 * 
 * Please don't complain about this code at this stage, I'm going to ignore it anyway.
 * In the future, I'll update this test case so it will create all the necessary
 * files so this all works, but don't hold your breath, it's not a priority.
 * 
 * Jon Eaves <jon@eaves.org>
 */
public class BCRampageTest extends TestCase
{

    public void testNotProvidingPKR()
    {
        String file = "e:/usr/home/pgptesting/tomcat.log";
        String recipient = "maddy@eaves.org";
        
        String[] args = new String[]{ "-e", "-R", recipient, file};
        PGPParams params = processArgs(args);
        assertTrue("Found errors processing arguments", !params.isError());
        assertNull("Missing the public key", params.getPublicKeyRingFile());
    }
    
    public void testNotProvidingRecipient()
    {
        String file = "e:/usr/home/pgptesting/tomcat.log";
        String keyDir = "c:/gnupg";
        
        String[] args = new String[]{ "-e", "-K", keyDir, file};
        PGPParams params = processArgs(args);
        assertTrue("Found errors processing arguments", !params.isError());
        assertNull("Missing the recipient", params.getRecipient());
    }
    
    public void testNotProvidingFile()
    {
        String keyDir = "c:/gnupg";
        String recipient = "maddy@eaves.org";
        
        String[] args = new String[]{ "-e", "-K", keyDir, "-R", recipient };
        PGPParams params = processArgs(args);
        assertTrue("Found no errors processing arguments", params.isError());  // not an argument error
        assertNull("Missing the input file", params.getInputFile());
    }
    
    public void testEncryptFile()
    {
        String file = "e:/usr/home/pgptesting/tomcat.log";
        String keyDir = "c:/gnupg";
        String recipient = "boo@eaves.org";
        
        runEncrypt(file, keyDir, recipient, false);
        assertTrue("Processing completed successfully", true);
    }
    
    public void testAsciiArmorEncryptFile()
    {
        String file = "e:/usr/home/pgptesting/index.html";
        String keyDir = "c:/gnupg";
        String recipient = "jon@eaves.org";
        
        runEncrypt(file, keyDir, recipient, true);
        assertTrue("Processing completed successfully", true);
    }
    
    private void runEncrypt(String file, String keyDir, String recipient, boolean armor)
    {
        String[] args = new String[]{ "-e", "-K", keyDir, "-R", recipient, file };
        
        if (armor)
        {
            args[0] = "-ea";
        }
        PGPParams params = processArgs(args);
        assertTrue("Found errors processing arguments", !params.isError());
        runEngine(params);
    }

    private void runEngine(PGPParams params)
    {
        PGPRampageEngine engine = new PGPRampageEngine(params);
        engine.process();
    }

    private PGPParams processArgs(String[] args)
    {
        BCRampage rampage = new BCRampage();
        PGPParams params = rampage.processArguments(args);
        if (params.isError())
        {
            System.out.println(params.getErrors());
        }
        return params;
    }

}
