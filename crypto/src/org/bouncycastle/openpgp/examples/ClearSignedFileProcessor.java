package org.bouncycastle.openpgp.examples;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * A simple utility class that creates clear signed files and verifies them.
 * <p>
 * To sign a file: ClearSignedFileProcessor -s fileName secretKey passPhrase.<br>
 * If -a is specified the output file will be "ascii-armored".
 * <p>
 * To decrypt: ClearSignedFileProcessor -v fileName signatureFile publicKeyFile.
 * <p>
 * Note: This example does not dash escape the input on signing or look for dash escaping on verification. See section 7 of RFC 2440 for further details.
 */
public class ClearSignedFileProcessor
{
    /**
     * A simple routine that opens a key ring file and loads the first available key suitable for
     * signature generation.
     * 
     * @param in
     * @return
     * @throws IOException
     * @throws PGPException
     */
    private static PGPSecretKey readSecretKey(
        InputStream    in)
        throws IOException, PGPException
    {    
        PGPSecretKeyRingCollection        pgpSec = new PGPSecretKeyRingCollection(in);

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        PGPSecretKey    key = null;
        
        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpSec.getKeyRings();
        
        while (key == null && rIt.hasNext())
        {
            PGPSecretKeyRing    kRing = (PGPSecretKeyRing)rIt.next();    
            Iterator                        kIt = kRing.getSecretKeys();
            
            while (key == null && kIt.hasNext())
            {
                PGPSecretKey    k = (PGPSecretKey)kIt.next();
                
                if (k.isSigningKey())
                {
                    key = k;
                }
            }
        }
        
        if (key == null)
        {
            throw new IllegalArgumentException("Can't find signing key in key ring.");
        }
        
        return key;
    }
    
    /**
     * verify a SHA1 clear text signed file
     */
    private static void verifyFile(
        InputStream        in,
        InputStream        keyIn)
        throws Exception
    {
        ArmoredInputStream    aIn = new ArmoredInputStream(in);

        //
        // read the input, making sure we ingore the last newline.
        //
        int                   ch;
        boolean               newLine = false;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        while ((ch = aIn.read()) >= 0 && aIn.isClearText())
        {
            if (newLine)
            {
                bOut.write((byte)'\n');
                newLine = false;
            }
            if (ch == '\n')
            {
                newLine = true;
                continue;
            }

            bOut.write((byte)ch);
        }
        
        PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(keyIn);

        PGPObjectFactory           pgpFact = new PGPObjectFactory(aIn);
        PGPSignatureList           p3 = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature               sig = p3.get(0);

        sig.initVerify(pgpRings.getPublicKey(sig.getKeyID()), "BC");

        sig.update(bOut.toByteArray());

        if (sig.verify())
        {
            System.out.println("signature verified.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }

    /**
     * create a clear text signed file.
     */
    private static void signFile(
        String          fileName,
        InputStream     keyIn,
        OutputStream    out,
        char[]          pass)
        throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException
    {    
        PGPSecretKey                    pgpSecKey = readSecretKey(keyIn);
        PGPPrivateKey                   pgpPrivKey = pgpSecKey.extractPrivateKey(pass, "BC");        
        PGPSignatureGenerator           sGen = new PGPSignatureGenerator(pgpSecKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1, "BC");
        PGPSignatureSubpacketGenerator  spGen = new PGPSignatureSubpacketGenerator();
        
        sGen.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey);
        
        Iterator    it = pgpSecKey.getPublicKey().getUserIDs();
        if (it.hasNext())
        {
            spGen.setSignerUserID(false, (String)it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }
        
        FileInputStream        fIn = new FileInputStream(fileName);
        int                    ch = 0;
        
        ArmoredOutputStream    aOut = new ArmoredOutputStream(out);
        
        aOut.beginClearText(PGPUtil.SHA1);

        boolean newLine = false;

        //
        // note the last \n in the file is ignored
        //
        while ((ch = fIn.read()) >= 0)
        {
            aOut.write(ch);
            if (newLine)
            {
                sGen.update((byte)'\n');
                newLine = false;
            }
            if (ch == '\n')
            {
                newLine = true;
                continue;
            }
            sGen.update((byte)ch);
        }
        
        aOut.endClearText();
        
        BCPGOutputStream            bOut = new BCPGOutputStream(aOut);
        
        sGen.generate().encode(bOut);

        aOut.close();
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args[0].equals("-s"))
        {
            InputStream        keyIn = PGPUtil.getDecoderStream(new FileInputStream(args[2]));
            FileOutputStream   out = new FileOutputStream(args[1] + ".asc");
            
            signFile(args[1], keyIn, out, args[3].toCharArray());
        }
        else if (args[0].equals("-v"))
        {
            FileInputStream    in = new FileInputStream(args[1]);
            InputStream        keyIn = PGPUtil.getDecoderStream(new FileInputStream(args[2]));
                
            verifyFile(in, keyIn);
        }
        else
        {
            System.err.println("usage: ClearSignedFileProcessor [-s file keyfile passPhrase]|[-v sigFile keyFile]");
        }
    }
}
