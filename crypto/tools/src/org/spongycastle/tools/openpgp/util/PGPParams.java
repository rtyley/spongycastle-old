package org.bouncycastle.tools.openpgp.util;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

public class PGPParams
{
    public static final String BINARY_SUFFIX      = ".gpg";
    public static final String ASCII_SUFFIX       = ".asc";

    private boolean            _encrypting        = false;
    private boolean            _decrypting        = false;
    private boolean            _signing           = false;
    private boolean            _verify            = false;

    private File               _secretKeyRingFile = null;
    private File               _publicKeyRingFile = null;
    private File               _inputFile         = null;
    private String             _outputFilename    = null;
    private String             _passPhrase        = null;
    private String             _keyPassPhrase     = null;
    private boolean            _mdcRequired       = false;
    private boolean            _pgp2Compatible    = false;
    private String             _recipient         = null;
    private String             _signor            = null;
    private boolean            _armor             = false;

    private boolean            _error             = false;
    private Collection         _errorMgs          = null;

    public boolean isError()
    {
        return _error;
    }

    public void addError(String string)
    {
        if (_errorMgs == null)
        {
            _errorMgs = new ArrayList();
            _error = true;
        }
        _errorMgs.add(string);
    }

    public Collection getErrors()
    {
        return _errorMgs;
    }

    public boolean isEncrypting()
    {
        return _encrypting;
    }

    public void setEncrypting(boolean encrypting)
    {
        _encrypting = encrypting;
    }

    public File getInputFile()
    {
        return _inputFile;
    }

    public void setInputFile(File inputFile)
    {
        _inputFile = inputFile;
    }

    public String getOutputFilename()
    {
        return _outputFilename;
    }

    public void setOutputFilename(String outputFilename)
    {
        _outputFilename = outputFilename;
    }

    public String getKeyPassPhrase()
    {
        return _keyPassPhrase;
    }

    public void setKeyPassPhrase(String keyPassPhrase)
    {
        _keyPassPhrase = keyPassPhrase;
    }

    public void setPassPhrase(String passPhrase)
    {
        _passPhrase = passPhrase;
    }
    
    public String getPassPhrase()
    {
        return _passPhrase;
    }

    public File getPublicKeyRingFile()
    {
        return _publicKeyRingFile;
    }

    public void setPublicKeyRingFile(File publicKeyRingFile)
    {
        _publicKeyRingFile = publicKeyRingFile;
    }

    public File getSecretKeyRingFile()
    {
        return _secretKeyRingFile;
    }

    public void setSecretKeyRingFile(File secretKeyRingFile)
    {
        _secretKeyRingFile = secretKeyRingFile;
    }

    public String getRecipient()
    {
        return _recipient;
    }

    public void setRecipient(String recipient)
    {
        _recipient = recipient;
    }

    public String getSignor()
    {
        return _signor;
    }

    public void setSignor(String signor)
    {
        _signor = signor;
    }

    public boolean isSigning()
    {
        return _signing;
    }

    public void setSigning(boolean signing)
    {
        _signing = signing;
    }

    public void setMDCRequired(boolean mdc)
    {
        _mdcRequired = mdc;
        if (mdc) {
            // Cannot be PGP 2 compatible if MDC required
            _pgp2Compatible = false;
        }
    }

    public boolean isMDCRequired()
    {
        return _mdcRequired;
    }

    public void setPGP2Compatible(boolean pgp2)
    {
        _pgp2Compatible = pgp2;
        if (pgp2) {
            // Cannot have MDC if PGP 2 compatible
            _mdcRequired = false;
        }
    }

    public boolean isPGP2Compatible()
    {
        return _pgp2Compatible;
    }

    public void setVerify(boolean verify)
    {
        _verify = verify;
    }

    public boolean isVerify()
    {
        return _verify;
    }

    public void setDecrypting(boolean decrypting)
    {
        _decrypting = decrypting;
    }

    public boolean isDecrypting()
    {
        return _decrypting;
    }

    public void setAsciiArmor(boolean armor)
    {
        _armor = armor;
    }

    public boolean isAsciiArmor()
    {
        return _armor;
    }

}
