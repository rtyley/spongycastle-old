package javax.crypto.spec;

import java.security.spec.KeySpec;

/**
 * A user-chosen password that can be used with password-based encryption
 * (<i>PBE</i>).
 * <p>
 * The password can be viewed as some kind of raw key material, from which
 * the encryption mechanism that uses it derives a cryptographic key.
 * <p>
 * Different PBE mechanisms may consume different bits of each password
 * character. For example, the PBE mechansim defined in
 * <a href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-5.html">PKCS #5</a>
 * looks at only the low order 8 bits of each character, whereas
 * <a href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-12.html">PKCS #12</a>
 * looks at all 16 bits of each character.
 * <p>
 * You convert the password characters to a PBE key by creating an
 * instance of the appropriate secret-key factory. For example, a secret-key
 * factory for PKCS #5 will construct a PBE key from only the low order 8 bits
 * of each password character, whereas a secret-key factory for PKCS #12 will
 * take all 16 bits of each character.
 * <p>
 * Also note that this class stores passwords as char arrays instead of
 * <code>String</code> objects (which would seem more logical), because the 
 * String class is immutable and there is no way to overwrite its
 * internal value when the password stored in it is no longer needed. Hence,
 * this class requests the password as a char array, so it can be overwritten
 * when done.
 *
 * @see javax.crypto.SecretKeyFactory
 * @see PBEParameterSpec
 */
public class PBEKeySpec
    implements KeySpec
{
    private char[]  password;

    /**
     * Constructor that takes a password.
     * <p>
     * Note that the given password is cloned before it is stored in
     * the new <code>PBEKeySpec</code> object.
     *
     * @param password - the password.
     */
    public PBEKeySpec(
        char[]  password)
    {
        this.password = (char[])password.clone();
    }

    /**
     * Returns the password.
     * <p>
     * Note that this method returns a reference to the password. It is
     * the caller's responsibility to zero out the password information after
     * it is no longer needed.
     *
     * @return the password
     */
    public final char[] getPassword()
    {
        return password;
    }
}
