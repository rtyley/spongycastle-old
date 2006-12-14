package org.bouncycastle.openpgp.examples.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.openpgp.examples.DSAElGamalKeyRingGenerator;
import org.bouncycastle.openpgp.examples.KeyBasedFileProcessor;
import org.bouncycastle.openpgp.examples.KeyBasedLargeFileProcessor;
import org.bouncycastle.openpgp.examples.PBEFileProcessor;
import org.bouncycastle.openpgp.examples.RSAKeyPairGenerator;
import org.bouncycastle.openpgp.examples.SignedFileProcessor;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;

public class AllTests
    extends TestCase
{
    private PrintStream _oldOut;
    private PrintStream _oldErr;
    
    private ByteArrayOutputStream _currentOut;
    private ByteArrayOutputStream _currentErr;
    
    public void setUp()
       throws Exception
    {
         _oldOut = System.out;
         _oldErr = System.err;
         _currentOut = new ByteArrayOutputStream();
         _currentErr = new ByteArrayOutputStream();
         
         System.setOut(new PrintStream(_currentOut));
         System.setErr(new PrintStream(_currentErr));
    }
    
    public void tearDown()
    {
        System.setOut(_oldOut);
        System.setOut(_oldErr);
    }
    
    public void testRSAKeyGeneration() 
        throws Exception
    {   
        RSAKeyPairGenerator.main(new String[] { "test", "password" });

        createSmallTestInput();
        createLargeTestInput();
        
        checkSigning("bpg");
        checkKeyBasedEncryption("bpg");
        checkLargeKeyBasedEncryption("bpg");
        
        RSAKeyPairGenerator.main(new String[] { "-a", "test", "password" });
        
        checkSigning("asc");
        checkKeyBasedEncryption("asc");
        checkLargeKeyBasedEncryption("asc");
    }
    
    public void testDSAElGamaleKeyGeneration() 
        throws Exception
    {   
        DSAElGamalKeyRingGenerator.main(new String[] { "test", "password" });
    
        createSmallTestInput();
        createLargeTestInput();
        
        checkSigning("bpg");
        checkKeyBasedEncryption("bpg");
        checkLargeKeyBasedEncryption("bpg");
        
        DSAElGamalKeyRingGenerator.main(new String[] { "-a", "test", "password" });
        
        checkSigning("asc");
        checkKeyBasedEncryption("asc");
        checkLargeKeyBasedEncryption("asc");
    }

    public void testPBEEncryption() 
        throws Exception
    {
        _currentErr.reset();
        
        PBEFileProcessor.main(new String[] { "-e", "test.txt", "password" });
        
        PBEFileProcessor.main(new String[] { "-d", "test.txt.bpg", "password" });
        
        assertEquals("no message integrity check", getLine(_currentErr));
        
        PBEFileProcessor.main(new String[] { "-e", "-i", "test.txt", "password" });
        
        PBEFileProcessor.main(new String[] { "-d", "test.txt.bpg", "password" });
        
        assertEquals("message integrity check passed", getLine(_currentErr));
        
        PBEFileProcessor.main(new String[] { "-e", "-ai", "test.txt", "password" });
        
        PBEFileProcessor.main(new String[] { "-d", "test.txt.asc", "password" });
        
        assertEquals("message integrity check passed", getLine(_currentErr));
    }
    
    private void checkSigning(String type) 
        throws Exception
    {
        _currentOut.reset();
        
        SignedFileProcessor.main(new String[] { "-s", "test.txt", "secret." + type, "password" });
        
        SignedFileProcessor.main(new String[] { "-v", "test.txt.bpg", "pub." + type });
        
        assertEquals("signature verified.", getLine(_currentOut));
        
        SignedFileProcessor.main(new String[] { "-s", "-a", "test.txt", "secret." + type, "password" });
        
        SignedFileProcessor.main(new String[] { "-v", "test.txt.asc", "pub." + type });
        
        assertEquals("signature verified.", getLine(_currentOut));
    }

    private void checkKeyBasedEncryption(String type) 
        throws Exception
    {
        _currentErr.reset();
        
        KeyBasedFileProcessor.main(new String[] { "-e", "test.txt", "pub." + type });
        
        KeyBasedFileProcessor.main(new String[] { "-d", "test.txt.bpg", "secret." + type, "password" });
        
        assertEquals("no message integrity check", getLine(_currentErr));
        
        KeyBasedFileProcessor.main(new String[] { "-e", "-i", "test.txt", "pub." + type });
        
        KeyBasedFileProcessor.main(new String[] { "-d", "test.txt.bpg", "secret." + type, "password" });
        
        assertEquals("message integrity check passed", getLine(_currentErr));
        
        KeyBasedFileProcessor.main(new String[] { "-e", "-ai", "test.txt", "pub." + type });
        
        KeyBasedFileProcessor.main(new String[] { "-d", "test.txt.asc", "secret." + type, "password" });
        
        assertEquals("message integrity check passed", getLine(_currentErr));
    }
    
    private void checkLargeKeyBasedEncryption(String type) 
        throws Exception
    {
        _currentErr.reset();
        
        KeyBasedLargeFileProcessor.main(new String[] { "-e", "large.txt", "pub." + type });
        
        KeyBasedLargeFileProcessor.main(new String[] { "-d", "large.txt.bpg", "secret." + type, "password" });
        
        assertEquals("no message integrity check", getLine(_currentErr));
        
        KeyBasedLargeFileProcessor.main(new String[] { "-e", "-i", "large.txt", "pub." + type });
        
        KeyBasedLargeFileProcessor.main(new String[] { "-d", "large.txt.bpg", "secret." + type, "password" });
        
        assertEquals("message integrity check passed", getLine(_currentErr));
        
        KeyBasedLargeFileProcessor.main(new String[] { "-e", "-ai", "large.txt", "pub." + type });
        
        KeyBasedLargeFileProcessor.main(new String[] { "-d", "large.txt.asc", "secret." + type, "password" });
        
        assertEquals("message integrity check passed", getLine(_currentErr));
    }
    
    private void createSmallTestInput() 
        throws IOException
    {
        BufferedWriter bfOut = new BufferedWriter(new FileWriter("test.txt"));
        
        bfOut.write("hello world!");
        bfOut.newLine();
        
        bfOut.close();
    }
    
    private void createLargeTestInput() 
        throws IOException
    {
        BufferedWriter bfOut = new BufferedWriter(new FileWriter("large.txt"));
        
        for (int i = 0; i != 2000; i++)
        {
            bfOut.write("hello world!");
            bfOut.newLine();
        }
        
        bfOut.close();
    }
    
    private String getLine(
        ByteArrayOutputStream out) 
        throws IOException
    {
        BufferedReader bRd = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(out.toByteArray())));
        
        out.reset();
        
        return bRd.readLine();
    }
    
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("OpenPGP Example Tests");
        
        suite.addTestSuite(AllTests.class);
        
        return suite;
    }
}
