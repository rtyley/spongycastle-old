package org.bouncycastle.tools.openpgp.dump;

import junit.framework.TestCase;

import org.bouncycastle.tools.openpgp.PGPDump;
import org.bouncycastle.tools.openpgp.util.PGPParams;

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
public class PGPDumpTest extends TestCase
{

    public void testSingleFileParameter()
    {
        String file = "e:/usr/home/pgptesting/forboo.gpg";
        PGPDump dump = new PGPDump();

        PGPParams params = dump.processArguments(new String[]{file});
        assertTrue("No errors in processing arguments", !params.isError());
        assertNotNull("File exists", params.getInputFile());
    }
    
    public void testProcessSignedAndEncryptedFile()
    {
        String file = "e:/usr/home/pgptesting/formaddy.gpg";
        String keyDir = "c:/gnupg";
        String passPhrase = "bouncy";
        
        runEncryptedFileTest(file, keyDir, passPhrase);
        
    }
    
    public void testProcessEncryptedFile()
    {
        String file = "e:/usr/home/pgptesting/forboo.gpg";
        String keyDir = "c:/gnupg";
        String passPhrase = "bouncy";
        
        runEncryptedFileTest(file, keyDir, passPhrase);
        
    }

    public void testProcessEncryptedArmoredFile()
    {
        String file = "e:/usr/home/pgptesting/index.html.asc";
        String keyDir = "c:/gnupg";
        String passPhrase = "bouncy";
        
        runEncryptedFileTest(file, keyDir, passPhrase);
        
    }
    
    private void runEncryptedFileTest(String file, String keyDir, String passPhrase)
    {
        PGPDump dump = new PGPDump();

        PGPParams params = dump.processArguments(new String[]{ "-K", keyDir, "-P", passPhrase, file });
        if (params.isError())
        {
            System.out.println(params.getErrors());
        }
        assertTrue("Found errors processing arguments", !params.isError());
        System.out.println("Dumping the file < "+file+" >");
        PGPDumpEngine engine = new PGPDumpEngine(params);
        engine.process();
        System.out.println();
    }

}
