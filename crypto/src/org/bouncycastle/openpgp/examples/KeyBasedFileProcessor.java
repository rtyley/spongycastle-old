package org.bouncycastle.openpgp.examples;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

/**
 * A simple utility class that encrypts/decrypts public key based
 * encryption files.
 * <p>
 * To encrypt a file: KeyBasedFileProcessor -e [-a|-ai] fileName publicKeyFile.<br>
 * If -a is specified the output file will be "ascii-armored".
 * If -i is specified the output file will be have integrity checking added.
 * <p>
 * To decrypt: KeyBasedFileProcessor -d fileName secretKeyFile passPhrase.
 * <p>
 * Note 1: this example will silently overwrite files, nor does it pay any attention to
 * the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase
 * will have been used.
 * <p>
 * Note 2: if an empty file name has been specified in the literal data object contained in the
 * encrypted packet a file with the name filename.out will be generated in the current working directory.
 */
public class KeyBasedFileProcessor
{
    /**
     * A simple routine that opens a key ring file and loads the first available key suitable for
     * encryption.
     * 
     * @param in
     * @return
     * @throws IOException
     * @throws PGPException
     */
    private static PGPPublicKey readPublicKey(
        InputStream    in)
        throws IOException, PGPException
    {
        in = PGPUtil.getDecoderStream(in);
        
        PGPPublicKeyRingCollection        pgpPub = new PGPPublicKeyRingCollection(in);

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        
        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();
        
        while (rIt.hasNext())
        {
            PGPPublicKeyRing    kRing = (PGPPublicKeyRing)rIt.next();    
            Iterator                        kIt = kRing.getPublicKeys();
            
            while (kIt.hasNext())
            {
                PGPPublicKey    k = (PGPPublicKey)kIt.next();
                
                if (k.isEncryptionKey())
                {
                    return k;
                }
            }
        }
        
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }
    
    /**
     * Search a secret key ring collection for a secret key corresponding to
     * keyID if it exists.
     * 
     * @param pgpSec a secret key ring collection.
     * @param keyID keyID we want.
     * @param pass passphrase to decrypt secret key with.
     * @return
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    private static PGPPrivateKey findSecretKey(
        PGPSecretKeyRingCollection  pgpSec,
        long                        keyID,
        char[]                      pass)
        throws PGPException, NoSuchProviderException
    {    
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        
        if (pgpSecKey == null)
        {
            return null;
        }
        
        return pgpSecKey.extractPrivateKey(pass, "BC");
    }
    
    /**
     * decrypt the passed in message stream
     */
    private static void decryptFile(
        InputStream in,
        InputStream keyIn,
        char[]      passwd,
        String      defaultFileName)
        throws Exception
    {
        in = PGPUtil.getDecoderStream(in);
        
        try
        {
            PGPObjectFactory pgpF = new PGPObjectFactory(in);
            PGPEncryptedDataList    enc;

            Object                  o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList)o;
            }
            else
            {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }
            
            //
            // find the secret key
            //
            Iterator                    it = enc.getEncryptedDataObjects();
            PGPPrivateKey               sKey = null;
            PGPPublicKeyEncryptedData   pbe = null;
            PGPSecretKeyRingCollection  pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn));

            while (sKey == null && it.hasNext())
            {
                pbe = (PGPPublicKeyEncryptedData)it.next();
                
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }
            
            if (sKey == null)
            {
                throw new IllegalArgumentException("secret key for message not found.");
            }
    
            InputStream         clear = pbe.getDataStream(sKey, "BC");
            
            PGPObjectFactory    plainFact = new PGPObjectFactory(clear);
            
            Object              message = plainFact.nextObject();
    
            if (message instanceof PGPCompressedData)
            {
                PGPCompressedData   cData = (PGPCompressedData)message;
                PGPObjectFactory    pgpFact = new PGPObjectFactory(cData.getDataStream());
                
                message = pgpFact.nextObject();
            }
            
            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData      ld = (PGPLiteralData)message;
                String              outFileName = ld.getFileName();
                if (ld.getFileName().length() == 0)
                {
                    outFileName = defaultFileName;
                }
                FileOutputStream    fOut = new FileOutputStream(outFileName);
                
                InputStream    unc = ld.getInputStream();
                int    ch;
                
                while ((ch = unc.read()) >= 0)
                {
                    fOut.write(ch);
                }
            }
            else if (message instanceof PGPOnePassSignatureList)
            {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected())
            {
                if (!pbe.verify())
                {
                    System.err.println("message failed integrity check");
                }
                else
                {
                    System.err.println("message integrity check passed");
                }
            }
            else
            {
                System.err.println("no message integrity check");
            }
        }
        catch (PGPException e)
        {
            System.err.println(e);
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    private static void encryptFile(
        OutputStream    out,
        String          fileName,
        PGPPublicKey    encKey,
        boolean         armor,
        boolean         withIntegrityCheck)
        throws IOException, NoSuchProviderException
    {    
        if (armor)
        {
            out = new ArmoredOutputStream(out);
        }
        
        try
        {
            ByteArrayOutputStream       bOut = new ByteArrayOutputStream();
            
    
            PGPCompressedDataGenerator  comData = new PGPCompressedDataGenerator(
                                                                    PGPCompressedData.ZIP);
                                                                    
            PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
            
            comData.close();
            
            PGPEncryptedDataGenerator   cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(), "BC");
                
            cPk.addMethod(encKey);
            
            byte[]                bytes = bOut.toByteArray();
            
            OutputStream    cOut = cPk.open(out, bytes.length);

            cOut.write(bytes);
            
            cOut.close();

            out.close();
        }
        catch (PGPException e)
        {
            System.err.println(e);
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    public static void main(
        String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length == 0)
        {
            System.err.println("usage: KeyBasedFileProcessor -e|-d [-a|ai] file [secretKeyFile passPhrase|pubKeyFile]");
            return;
        }
        
        if (args[0].equals("-e"))
        {
            if (args[1].equals("-a") || args[1].equals("-ai") || args[1].equals("-ia"))
            {
                FileInputStream     keyIn = new FileInputStream(args[3]);
                FileOutputStream    out = new FileOutputStream(args[2] + ".asc");
                encryptFile(out, args[2], readPublicKey(keyIn), true, (args[1].indexOf('i') > 0));
            }
            else if (args[1].equals("-i"))
            {
                FileInputStream     keyIn = new FileInputStream(args[3]);
                FileOutputStream    out = new FileOutputStream(args[2] + ".bpg");
                encryptFile(out, args[2], readPublicKey(keyIn), false, true);
            }
            else
            {
                FileInputStream     keyIn = new FileInputStream(args[2]);
                FileOutputStream    out = new FileOutputStream(args[1] + ".bpg");
                encryptFile(out, args[1], readPublicKey(keyIn), false, false);
            }
        }
        else if (args[0].equals("-d"))
        {
            FileInputStream    in = new FileInputStream(args[1]);
            FileInputStream    keyIn = new FileInputStream(args[2]);
            decryptFile(in, keyIn, args[3].toCharArray(), new File(args[1]).getName() + ".out");
        }
        else
        {
            System.err.println("usage: KeyBasedFileProcessor -d|-e [-a|ai] file [secretKeyFile passPhrase|pubKeyFile]");
        }
    }
}
