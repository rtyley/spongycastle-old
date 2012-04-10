package org.bouncycastle.tools.openpgp.util;

import java.io.File;


/**
 * 
 */
public class PGPCmdLineArgProcessor
{
    private static final String PGP_DEFAULT_PUBLIC_RING = "pubring.gpg";
    private static final String PGP_DEFAULT_SECRET_RING = "secring.gpg";
    
    public PGPParams processArguments(String[] args)
    {
        PGPParams rv = new PGPParams();
        int count = 0;
        
        while (count != args.length)
        {
            String arg = args[count++];

            if (arg.equals("-e"))
            {
                rv.setEncrypting(true);
                rv.setAsciiArmor(false);
            } 
            else if (arg.equals("-ea"))
            {
                rv.setEncrypting(true);
                rv.setAsciiArmor(true);
            }
            else if (arg.equals("-s"))
            {
                rv.setSigning(true);
                rv.setAsciiArmor(false);
            }
            else if (arg.equals("-sa"))
            {
                rv.setSigning(true);
                rv.setAsciiArmor(true);
            }
            else if (arg.equals("-se"))
            {
                rv.setSigning(true);
                rv.setEncrypting(true);
                rv.setAsciiArmor(false);
            } 
            else if (arg.equals("-sea"))
            {
                rv.setSigning(true);
                rv.setEncrypting(true);
                rv.setAsciiArmor(true);
            }
            else if (arg.equals("-v"))
            {
                rv.setVerify(true);
            }
            else if (arg.equals("-d"))
            {
                rv.setDecrypting(true);
            }
            else if (arg.equals("-K"))
            {
                String keyRingDir = args[count++];
                if (!checkDirectory(keyRingDir))
                {
                    rv.addError("Cannot find key ring directory [" + keyRingDir + "]");
                }
                String pubRing = keyRingDir + File.separator + PGP_DEFAULT_PUBLIC_RING;
                String secRing = keyRingDir + File.separator + PGP_DEFAULT_SECRET_RING;
                processPubRing(pubRing, rv);
                processSecRing(secRing, rv);

            }
            else if (arg.equals("-skr"))
            {
                String fileName = args[count++];
                processSecRing(fileName, rv);
            }
            else if (arg.equals("-pkr"))
            {
                String fileName = args[count++];
                processPubRing(fileName, rv);
            }
            else if (arg.equals("-P"))
            {
                rv.setKeyPassPhrase(args[count++]);
            }
            else if (arg.equals("-R"))
            {
                rv.setRecipient(args[count++]);
            }
            else if (arg.equals("-u"))
            {
                rv.setSignor(args[count++]);
            }
            else if (arg.equals("-o"))
            {
                rv.setOutputFilename(args[count++]);
            }
            else if (arg.equals("-pbe"))
            {
                rv.setPassPhrase(args[count++]);
            }
            else if (arg.equals("-mdc")) // if specified, set to true
            {
                rv.setMDCRequired(true);
            }
            else if (arg.equals("-pgp2")) // if specified, set to true
            {
                rv.setPGP2Compatible(true);
            }
            else if (arg.startsWith("-"))
            {
                rv.addError("Unknown option [" + arg + "]");
            }
            else
            {
                String fileName = arg;
                File file = new File(fileName);
                if (!file.exists())
                {
                    rv.addError("Input file does not exist [" + fileName + "]");
                }
                else
                {
                    rv.setInputFile(file);
                }
            }
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
