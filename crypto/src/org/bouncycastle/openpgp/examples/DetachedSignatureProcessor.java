package org.bouncycastle.openpgp.examples;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * A simple utility class that creates seperate signatures for files and verifies them.
 * <p>
 * To sign a file: DetachedSignatureProcessor -s [-a] fileName secretKey passPhrase.<br>
 * If -a is specified the output file will be "ascii-armored".
 * <p>
 * To decrypt: DetachedSignatureProcessor -v  fileName signatureFile publicKeyFile.
 * <p>
 * Note: this example will silently overwrite files.
 * It also expects that a single pass phrase
 * will have been used.
 */
public class DetachedSignatureProcessor
{
    /**
     * verify the signature in in against the file fileName.
     */
    private static void verifySignature(
        String          fileName,
        InputStream     in,
        InputStream     keyIn)
        throws Exception
    {
        in = PGPUtil.getDecoderStream(in);
        
        PGPObjectFactory    pgpFact = new PGPObjectFactory(in);
        PGPSignatureList    p3 = null;

        Object    o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData)
        {
            PGPCompressedData             c1 = (PGPCompressedData)o;

            pgpFact = new PGPObjectFactory(c1.getDataStream());
            
            p3 = (PGPSignatureList)pgpFact.nextObject();
        }
        else
        {
            p3 = (PGPSignatureList)o;
        }
            
        PGPPublicKeyRingCollection  pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn));


        InputStream                 dIn = new FileInputStream(fileName);
        int                                     ch;

        PGPSignature                sig = p3.get(0);
        PGPPublicKey                key = pgpPubRingCollection.getPublicKey(sig.getKeyID());

        sig.initVerify(key, "BC");

        while ((ch = dIn.read()) >= 0)
        {
            sig.update((byte)ch);
        }

        if (sig.verify())
        {
            System.out.println("signature verified.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }

    private static void createSignature(
        String          fileName,
        InputStream     keyIn,
        OutputStream    out,
        char[]          pass,
        boolean         armor)
        throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException
    {    
        if (armor)
        {
            out = new ArmoredOutputStream(out);
        }
        
        PGPSecretKey             pgpSec = PGPExampleUtil.readSecretKey(keyIn);
        PGPPrivateKey            pgpPrivKey = pgpSec.extractPrivateKey(pass, "BC");        
        PGPSignatureGenerator    sGen = new PGPSignatureGenerator(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1, "BC");
        
        sGen.initSign(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
        
        BCPGOutputStream         bOut = new BCPGOutputStream(out);
        
        FileInputStream          fIn = new FileInputStream(fileName);
        int                      ch = 0;
        
        while ((ch = fIn.read()) >= 0)
        {
            sGen.update((byte)ch);
        }
        
        sGen.generate().encode(bOut);
        
        out.close();
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args[0].equals("-s"))
        {
            if (args[1].equals("-a"))
            {
                FileInputStream     keyIn = new FileInputStream(args[3]);
                FileOutputStream    out = new FileOutputStream(args[2] + ".asc");
                
                createSignature(args[2], keyIn, out, args[4].toCharArray(), true);
            }
            else
            {
                FileInputStream     keyIn = new FileInputStream(args[2]);
                FileOutputStream    out = new FileOutputStream(args[1] + ".bpg");
                
                createSignature(args[1], keyIn, out, args[3].toCharArray(), false);
            }
        }
        else if (args[0].equals("-v"))
        {
            FileInputStream    in = new FileInputStream(args[2]);
            FileInputStream    keyIn = new FileInputStream(args[3]);
            
            verifySignature(args[1], in, keyIn);
        }
        else
        {
            System.err.println("usage: DetachedSignatureProcessor [-s [-a] file keyfile passPhrase]|[-v file sigFile keyFile]");
        }
    }
}
