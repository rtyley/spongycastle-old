package org.spongycastle.jce.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Iterator;
import java.util.Map;

import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.bc.BCObjectIdentifiers;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.asn1.iana.IANAObjectIdentifiers;
import org.spongycastle.asn1.nist.NISTObjectIdentifiers;
import org.spongycastle.asn1.oiw.OIWObjectIdentifiers;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.spongycastle.jce.interfaces.ConfigurableProvider;

/**
 * To add the provider at runtime use:
 * <pre>
 * import java.security.Security;
 * import org.spongycastle.jce.provider.BouncyCastleProvider;
 *
 * Security.addProvider(new BouncyCastleProvider());
 * </pre>
 * The provider can also be configured as part of your environment via
 * static registration by adding an entry to the java.security properties
 * file (found in $JAVA_HOME/jre/lib/security/java.security, where
 * $JAVA_HOME is the location of your JDK/JRE distribution). You'll find
 * detailed instructions in the file but basically it comes down to adding
 * a line:
 * <pre>
 * <code>
 *    security.provider.&lt;n&gt;=org.spongycastle.jce.provider.BouncyCastleProvider
 * </code>
 * </pre>
 * Where &lt;n&gt; is the preference you want the provider at (1 being the
 * most preferred).
 * <p>Note: JCE algorithm names should be upper-case only so the case insensitive
 * test for getInstance works.
 */
public final class BouncyCastleProvider extends Provider
    implements ConfigurableProvider
{
    private static final String PROVIDER_PACKAGE_NAME = BouncyCastleProvider.class.getPackage().getName();

	private static String info = "BouncyCastle Security Provider v1.46";

	public static String PROVIDER_NAME = "SC";

    /*
     * Configurable symmetric ciphers
     */
    private static final String SYMMETRIC_CIPHER_PACKAGE = PROVIDER_PACKAGE_NAME+ ".symmetric.";
    private static final String[] SYMMETRIC_CIPHERS =
    {
        "AES", "ARC4", "Blowfish", "Camellia", "CAST5", "CAST6", "DESede", "Grainv1", "Grain128", "HC128", "HC256", "IDEA",
        "Noekeon", "RC5", "RC6", "Rijndael", "Salsa20", "SEED", "Serpent", "Skipjack", "TEA", "Twofish", "VMPC", "VMPCKSA3", "XTEA"
    };

    /*
     * Configurable asymmetric ciphers
     */
    private static final String ASYMMETRIC_CIPHER_PACKAGE = PROVIDER_PACKAGE_NAME+ ".asymmetric.";
    private static final String[] ASYMMETRIC_CIPHERS =
    {
        "EC"
    };

    /**
     * Construct a new provider.  This should only be required when
     * using runtime registration of the provider using the
     * <code>Security.addProvider()</code> mechanism.
     */
    public BouncyCastleProvider()
    {
        super(PROVIDER_NAME, 1.46, info);

        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                setup();
                return null;
            }
        });
    }

    private void setup()
    {
        loadAlgorithms(SYMMETRIC_CIPHER_PACKAGE, SYMMETRIC_CIPHERS);
        loadAlgorithms(ASYMMETRIC_CIPHER_PACKAGE, ASYMMETRIC_CIPHERS);

        //
        // X509Store
        //
        put("X509Store.CERTIFICATE/COLLECTION", PROVIDER_PACKAGE_NAME+".X509StoreCertCollection");
        put("X509Store.ATTRIBUTECERTIFICATE/COLLECTION", PROVIDER_PACKAGE_NAME+".X509StoreAttrCertCollection");
        put("X509Store.CRL/COLLECTION", PROVIDER_PACKAGE_NAME+".X509StoreCRLCollection");
        put("X509Store.CERTIFICATEPAIR/COLLECTION", PROVIDER_PACKAGE_NAME+".X509StoreCertPairCollection");

        put("X509Store.CERTIFICATE/LDAP", PROVIDER_PACKAGE_NAME+".X509StoreLDAPCerts");
        put("X509Store.CRL/LDAP", PROVIDER_PACKAGE_NAME+".X509StoreLDAPCRLs");
        put("X509Store.ATTRIBUTECERTIFICATE/LDAP", PROVIDER_PACKAGE_NAME+".X509StoreLDAPAttrCerts");
        put("X509Store.CERTIFICATEPAIR/LDAP", PROVIDER_PACKAGE_NAME+".X509StoreLDAPCertPairs");
        
        //
        // X509StreamParser
        //
        put("X509StreamParser.CERTIFICATE", PROVIDER_PACKAGE_NAME+".X509CertParser");
        put("X509StreamParser.ATTRIBUTECERTIFICATE", PROVIDER_PACKAGE_NAME+".X509AttrCertParser");
        put("X509StreamParser.CRL", PROVIDER_PACKAGE_NAME+".X509CRLParser");
        put("X509StreamParser.CERTIFICATEPAIR", PROVIDER_PACKAGE_NAME+".X509CertPairParser");


        //
        // KeyStore
        //
        put("KeyStore.BKS", PROVIDER_PACKAGE_NAME+".JDKKeyStore");
        put("KeyStore.BouncyCastle", PROVIDER_PACKAGE_NAME+".JDKKeyStore$BouncyCastleStore");
        put("KeyStore.PKCS12", PROVIDER_PACKAGE_NAME+".JDKPKCS12KeyStore$BCPKCS12KeyStore");
        put("KeyStore.BCPKCS12", PROVIDER_PACKAGE_NAME+".JDKPKCS12KeyStore$BCPKCS12KeyStore");
        put("KeyStore.PKCS12-DEF", PROVIDER_PACKAGE_NAME+".JDKPKCS12KeyStore$DefPKCS12KeyStore");

        put("KeyStore.PKCS12-3DES-40RC2", PROVIDER_PACKAGE_NAME+".JDKPKCS12KeyStore$BCPKCS12KeyStore");
        put("KeyStore.PKCS12-3DES-3DES", PROVIDER_PACKAGE_NAME+".JDKPKCS12KeyStore$BCPKCS12KeyStore3DES");

        put("KeyStore.PKCS12-DEF-3DES-40RC2", PROVIDER_PACKAGE_NAME+".JDKPKCS12KeyStore$DefPKCS12KeyStore");
        put("KeyStore.PKCS12-DEF-3DES-3DES", PROVIDER_PACKAGE_NAME+".JDKPKCS12KeyStore$DefPKCS12KeyStore3DES");

        put("Alg.Alias.KeyStore.UBER", "BouncyCastle");
        put("Alg.Alias.KeyStore.BOUNCYCASTLE", "BouncyCastle");
        put("Alg.Alias.KeyStore.spongycastle", "BouncyCastle");

        //
        // certificate factories.
        //
        put("CertificateFactory.X.509", PROVIDER_PACKAGE_NAME+".JDKX509CertificateFactory");
        put("Alg.Alias.CertificateFactory.X509", "X.509");

        //
        // algorithm parameter generators
        //
        put("AlgorithmParameterGenerator.DH", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$DH");
        put("AlgorithmParameterGenerator.DSA", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$DSA");
        put("AlgorithmParameterGenerator.GOST3410", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$GOST3410");
        put("AlgorithmParameterGenerator.ELGAMAL", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$ElGamal");
        put("AlgorithmParameterGenerator.DES", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$DES");
        put("AlgorithmParameterGenerator.DESEDE", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$DES");
        put("AlgorithmParameterGenerator." + PKCSObjectIdentifiers.des_EDE3_CBC, PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$DES");
        put("AlgorithmParameterGenerator." + OIWObjectIdentifiers.desCBC, PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$DES");
        put("AlgorithmParameterGenerator.RC2", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$RC2");
        put("AlgorithmParameterGenerator.1.2.840.113549.3.2", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameterGenerator$RC2");

        put("Alg.Alias.AlgorithmParameterGenerator.DIFFIEHELLMAN", "DH");
        put("Alg.Alias.AlgorithmParameterGenerator.GOST-3410", "GOST3410");
        //
        // algorithm parameters
        //
        put("AlgorithmParameters.OAEP", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$OAEP");
        put("AlgorithmParameters.PSS", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$PSS");
        put("AlgorithmParameters.DH", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$DH");
        put("Alg.Alias.AlgorithmParameters.DIFFIEHELLMAN", "DH");
        put("AlgorithmParameters.DSA", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$DSA");
        put("AlgorithmParameters.ELGAMAL", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$ElGamal");
        put("AlgorithmParameters.IES", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$IES");
        put("AlgorithmParameters.PKCS12PBE", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$PKCS12PBE");
        put("AlgorithmParameters." + PKCSObjectIdentifiers.des_EDE3_CBC, PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$IVAlgorithmParameters");
        put("AlgorithmParameters." + PKCSObjectIdentifiers.id_PBKDF2, PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$PBKDF2");

        put("AlgorithmParameters.GOST3410", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$GOST3410");
        put("Alg.Alias.AlgorithmParameters.GOST-3410", "GOST3410");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1ANDRC2", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND3-KEYTRIPLEDES", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND2-KEYTRIPLEDES", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDRC2", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDRC4", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1ANDRC2-CBC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDDES3KEY-CBC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDDES2KEY-CBC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND40BITRC2-CBC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND40BITRC4", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITRC2-CBC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITRC4", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAANDTWOFISH-CBC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.1", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.2", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.3", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.4", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.5", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.12.1.6", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWithSHAAnd3KeyTripleDES", "PKCS12PBE");

        put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getId(), "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getId(), "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getId(), "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), "PKCS12PBE");

        put("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers.id_RSAES_OAEP, "OAEP");
        
        put("Alg.Alias.AlgorithmParameters.RSAPSS", "PSS");
        put("Alg.Alias.AlgorithmParameters.RSASSA-PSS", "PSS");
        put("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers.id_RSASSA_PSS, "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA1withRSA/PSS", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA224withRSA/PSS", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA256withRSA/PSS", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA384withRSA/PSS", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA512withRSA/PSS", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA1WITHRSAANDMGF1", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA224WITHRSAANDMGF1", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA256WITHRSAANDMGF1", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA384WITHRSAANDMGF1", "PSS");
        put("Alg.Alias.AlgorithmParameters.SHA512WITHRSAANDMGF1", "PSS");
        put("Alg.Alias.AlgorithmParameters.RAWRSAPSS", "PSS");
        put("Alg.Alias.AlgorithmParameters.NONEWITHRSAPSS", "PSS");
        put("Alg.Alias.AlgorithmParameters.NONEWITHRSASSA-PSS", "PSS");
        
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND128BITAES-CBC-BC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND192BITAES-CBC-BC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHAAND256BITAES-CBC-BC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND128BITAES-CBC-BC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND192BITAES-CBC-BC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA256AND256BITAES-CBC-BC", "PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND128BITAES-CBC-BC","PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND192BITAES-CBC-BC","PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA1AND256BITAES-CBC-BC","PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND128BITAES-CBC-BC","PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND192BITAES-CBC-BC","PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-1AND256BITAES-CBC-BC","PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND128BITAES-CBC-BC","PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND192BITAES-CBC-BC","PKCS12PBE");
        put("Alg.Alias.AlgorithmParameters.PBEWITHSHA-256AND256BITAES-CBC-BC","PKCS12PBE");

        put("AlgorithmParameters.SHA1WITHECDSA", PROVIDER_PACKAGE_NAME+".JDKECDSAAlgParameters$SigAlgParameters");
        put("AlgorithmParameters.SHA224WITHECDSA", PROVIDER_PACKAGE_NAME+".JDKECDSAAlgParameters$SigAlgParameters");
        put("AlgorithmParameters.SHA256WITHECDSA", PROVIDER_PACKAGE_NAME+".JDKECDSAAlgParameters$SigAlgParameters");
        put("AlgorithmParameters.SHA384WITHECDSA", PROVIDER_PACKAGE_NAME+".JDKECDSAAlgParameters$SigAlgParameters");
        put("AlgorithmParameters.SHA512WITHECDSA", PROVIDER_PACKAGE_NAME+".JDKECDSAAlgParameters$SigAlgParameters");
        
        //
        // key agreement
        //
        put("KeyAgreement.DH", PROVIDER_PACKAGE_NAME+".JCEDHKeyAgreement");
        put("Alg.Alias.KeyAgreement.DIFFIEHELLMAN", "DH");
        
        //
        // cipher engines
        //
        put("Cipher.DES", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$DES");
        put("Cipher." + OIWObjectIdentifiers.desCBC, PROVIDER_PACKAGE_NAME+".JCEBlockCipher$DESCBC");

        put("Cipher.RC2", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$RC2");
        put("Cipher.RC2WRAP", PROVIDER_PACKAGE_NAME+".WrapCipherSpi$RC2Wrap");
        put("Cipher.1.2.840.113549.1.9.16.3.7", PROVIDER_PACKAGE_NAME+".WrapCipherSpi$RC2Wrap");

        put("Cipher.1.2.840.113549.3.2", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$RC2CBC");
        
        put("Alg.Alias.Cipher.PBEWithSHAAnd3KeyTripleDES",  "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
        
        put("Cipher.GOST28147", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$GOST28147");
        put("Alg.Alias.Cipher.GOST", "GOST28147");
        put("Alg.Alias.Cipher.GOST-28147", "GOST28147");
        put("Cipher." + CryptoProObjectIdentifiers.gostR28147_cbc, PROVIDER_PACKAGE_NAME+".JCEBlockCipher$GOST28147cbc");

        put("Cipher.RSA", PROVIDER_PACKAGE_NAME+".JCERSACipher$NoPadding");
        put("Cipher.RSA/RAW", PROVIDER_PACKAGE_NAME+".JCERSACipher$NoPadding");
        put("Cipher.RSA/PKCS1", PROVIDER_PACKAGE_NAME+".JCERSACipher$PKCS1v1_5Padding");
        put("Cipher.1.2.840.113549.1.1.1", PROVIDER_PACKAGE_NAME+".JCERSACipher$PKCS1v1_5Padding");
        put("Cipher.2.5.8.1.1", PROVIDER_PACKAGE_NAME+".JCERSACipher$PKCS1v1_5Padding");
        put("Cipher.RSA/1", PROVIDER_PACKAGE_NAME+".JCERSACipher$PKCS1v1_5Padding_PrivateOnly");
        put("Cipher.RSA/2", PROVIDER_PACKAGE_NAME+".JCERSACipher$PKCS1v1_5Padding_PublicOnly");
        put("Cipher.RSA/OAEP", PROVIDER_PACKAGE_NAME+".JCERSACipher$OAEPPadding");
        put("Cipher." + PKCSObjectIdentifiers.id_RSAES_OAEP, PROVIDER_PACKAGE_NAME+".JCERSACipher$OAEPPadding");
        put("Cipher.RSA/ISO9796-1", PROVIDER_PACKAGE_NAME+".JCERSACipher$ISO9796d1Padding");

        put("Cipher.ECIES", PROVIDER_PACKAGE_NAME+".JCEIESCipher$ECIES");
        put("Cipher.BrokenECIES", PROVIDER_PACKAGE_NAME+".JCEIESCipher$BrokenECIES");
        put("Cipher.IES", PROVIDER_PACKAGE_NAME+".JCEIESCipher$IES");
        put("Cipher.BrokenIES", PROVIDER_PACKAGE_NAME+".JCEIESCipher$BrokenIES");
        put("Cipher.ELGAMAL", PROVIDER_PACKAGE_NAME+".JCEElGamalCipher$NoPadding");
        put("Cipher.ELGAMAL/PKCS1", PROVIDER_PACKAGE_NAME+".JCEElGamalCipher$PKCS1v1_5Padding");

        put("Alg.Alias.Cipher.RSA//RAW", "RSA");
        put("Alg.Alias.Cipher.RSA//NOPADDING", "RSA");
        put("Alg.Alias.Cipher.RSA//PKCS1PADDING", "RSA/PKCS1");
        put("Alg.Alias.Cipher.RSA//OAEPPADDING", "RSA/OAEP");
        put("Alg.Alias.Cipher.RSA//ISO9796-1PADDING", "RSA/ISO9796-1");
        
        put("Alg.Alias.Cipher.ELGAMAL/ECB/PKCS1PADDING", "ELGAMAL/PKCS1");
        put("Alg.Alias.Cipher.ELGAMAL/NONE/PKCS1PADDING", "ELGAMAL/PKCS1");
        put("Alg.Alias.Cipher.ELGAMAL/NONE/NOPADDING", "ELGAMAL");

        put("Cipher.PBEWITHMD5ANDDES", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithMD5AndDES");
        put("Cipher.BROKENPBEWITHMD5ANDDES", PROVIDER_PACKAGE_NAME+".BrokenJCEBlockCipher$BrokePBEWithMD5AndDES");
        put("Cipher.PBEWITHMD5ANDRC2", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithMD5AndRC2");
        put("Cipher.PBEWITHSHA1ANDDES", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithSHA1AndDES");
        put("Cipher.BROKENPBEWITHSHA1ANDDES", PROVIDER_PACKAGE_NAME+".BrokenJCEBlockCipher$BrokePBEWithSHA1AndDES");
        put("Cipher.PBEWITHSHA1ANDRC2", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithSHA1AndRC2");
        put("Cipher.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithSHAAndDES3Key");
        put("Cipher.BROKENPBEWITHSHAAND3-KEYTRIPLEDES-CBC", PROVIDER_PACKAGE_NAME+".BrokenJCEBlockCipher$BrokePBEWithSHAAndDES3Key");
        put("Cipher.OLDPBEWITHSHAAND3-KEYTRIPLEDES-CBC", PROVIDER_PACKAGE_NAME+".BrokenJCEBlockCipher$OldPBEWithSHAAndDES3Key");
        put("Cipher.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithSHAAndDES2Key");
        put("Cipher.BROKENPBEWITHSHAAND2-KEYTRIPLEDES-CBC", PROVIDER_PACKAGE_NAME+".BrokenJCEBlockCipher$BrokePBEWithSHAAndDES2Key");
        put("Cipher.PBEWITHSHAAND128BITRC2-CBC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithSHAAnd128BitRC2");
        put("Cipher.PBEWITHSHAAND40BITRC2-CBC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithSHAAnd40BitRC2");
        put("Cipher.PBEWITHSHAAND128BITRC4", PROVIDER_PACKAGE_NAME+".JCEStreamCipher$PBEWithSHAAnd128BitRC4");
        put("Cipher.PBEWITHSHAAND40BITRC4", PROVIDER_PACKAGE_NAME+".JCEStreamCipher$PBEWithSHAAnd40BitRC4");

        put("Alg.Alias.Cipher.PBEWITHSHA1AND3-KEYTRIPLEDES-CBC", "Cipher.PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
        put("Alg.Alias.Cipher.PBEWITHSHA1AND2-KEYTRIPLEDES-CBC", "Cipher.PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
        put("Alg.Alias.Cipher.PBEWITHSHA1AND128BITRC2-CBC", "Cipher.PBEWITHSHAAND128BITRC2-CBC");
        put("Alg.Alias.Cipher.PBEWITHSHA1AND40BITRC2-CBC", "Cipher.PBEWITHSHAAND40BITRC2-CBC");
        put("Alg.Alias.Cipher.PBEWITHSHA1AND128BITRC4", "Cipher.PBEWITHSHAAND128BITRC4");
        put("Alg.Alias.Cipher.PBEWITHSHA1AND40BITRC4", "Cipher.PBEWITHSHAAND40BITRC4");

        put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getId(), "PBEWITHSHAAND128BITAES-CBC-BC");
        put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getId(), "PBEWITHSHAAND192BITAES-CBC-BC");
        put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getId(), "PBEWITHSHAAND256BITAES-CBC-BC");
        put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), "PBEWITHSHA256AND128BITAES-CBC-BC");
        put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), "PBEWITHSHA256AND192BITAES-CBC-BC");
        put("Alg.Alias.Cipher." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), "PBEWITHSHA256AND256BITAES-CBC-BC");

        put("Cipher.PBEWITHSHAAND128BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        put("Cipher.PBEWITHSHAAND192BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        put("Cipher.PBEWITHSHAAND256BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        put("Cipher.PBEWITHSHA256AND128BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        put("Cipher.PBEWITHSHA256AND192BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        put("Cipher.PBEWITHSHA256AND256BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        put("Alg.Alias.Cipher.PBEWITHSHA1AND128BITAES-CBC-BC","PBEWITHSHAAND128BITAES-CBC-BC");
        put("Alg.Alias.Cipher.PBEWITHSHA1AND192BITAES-CBC-BC","PBEWITHSHAAND192BITAES-CBC-BC");
        put("Alg.Alias.Cipher.PBEWITHSHA1AND256BITAES-CBC-BC","PBEWITHSHAAND256BITAES-CBC-BC");
        put("Alg.Alias.Cipher.PBEWITHSHA-1AND128BITAES-CBC-BC","PBEWITHSHAAND128BITAES-CBC-BC");
        put("Alg.Alias.Cipher.PBEWITHSHA-1AND192BITAES-CBC-BC","PBEWITHSHAAND192BITAES-CBC-BC");
        put("Alg.Alias.Cipher.PBEWITHSHA-1AND256BITAES-CBC-BC","PBEWITHSHAAND256BITAES-CBC-BC");
        put("Alg.Alias.Cipher.PBEWITHSHA-256AND128BITAES-CBC-BC","PBEWITHSHA256AND128BITAES-CBC-BC");
        put("Alg.Alias.Cipher.PBEWITHSHA-256AND192BITAES-CBC-BC","PBEWITHSHA256AND192BITAES-CBC-BC");
        put("Alg.Alias.Cipher.PBEWITHSHA-256AND256BITAES-CBC-BC","PBEWITHSHA256AND256BITAES-CBC-BC");
        
        put("Cipher.PBEWITHMD5AND128BITAES-CBC-OPENSSL", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        put("Cipher.PBEWITHMD5AND192BITAES-CBC-OPENSSL", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        put("Cipher.PBEWITHMD5AND256BITAES-CBC-OPENSSL", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithAESCBC");
        
        put("Cipher.PBEWITHSHAANDTWOFISH-CBC", PROVIDER_PACKAGE_NAME+".JCEBlockCipher$PBEWithSHAAndTwofish");
        put("Cipher.OLDPBEWITHSHAANDTWOFISH-CBC", PROVIDER_PACKAGE_NAME+".BrokenJCEBlockCipher$OldPBEWithSHAAndTwofish");

        put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, "PBEWITHMD2ANDDES");
        put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC, "PBEWITHMD2ANDRC2");
        put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, "PBEWITHMD5ANDDES");
        put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC, "PBEWITHMD5ANDDES");
        put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, "PBEWITHSHA1ANDDES");
        put("Alg.Alias.Cipher." + PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC, "PBEWITHSHA1ANDRC2");

        put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.1", "PBEWITHSHAAND128BITRC4");
        put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.2", "PBEWITHSHAAND40BITRC4");
        put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.3", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
        put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.4", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
        put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.5", "PBEWITHSHAAND128BITRC2-CBC");
        put("Alg.Alias.Cipher.1.2.840.113549.1.12.1.6", "PBEWITHSHAAND40BITRC2-CBC");
        put("Alg.Alias.Cipher.PBEWITHSHA1ANDDESEDE", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
        //
        // key generators.
        //
        put("KeyGenerator.DES", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$DES");
        put("Alg.Alias.KeyGenerator." + OIWObjectIdentifiers.desCBC, "DES");

        put("KeyGenerator.RC2", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$RC2");
        put("KeyGenerator.1.2.840.113549.3.2", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$RC2");

        put("KeyGenerator.GOST28147", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$GOST28147");
        put("Alg.Alias.KeyGenerator.GOST", "GOST28147");
        put("Alg.Alias.KeyGenerator.GOST-28147", "GOST28147");
        put("Alg.Alias.KeyGenerator." + CryptoProObjectIdentifiers.gostR28147_cbc, "GOST28147");

        //
        // key pair generators.
        //
        put("KeyPairGenerator.RSA", PROVIDER_PACKAGE_NAME+".JDKKeyPairGenerator$RSA");
        put("KeyPairGenerator.DH", PROVIDER_PACKAGE_NAME+".JDKKeyPairGenerator$DH");
        put("KeyPairGenerator.DSA", PROVIDER_PACKAGE_NAME+".JDKKeyPairGenerator$DSA");
        put("KeyPairGenerator.ELGAMAL", PROVIDER_PACKAGE_NAME+".JDKKeyPairGenerator$ElGamal");

        put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1.1", "RSA");
        put("Alg.Alias.KeyPairGenerator.DIFFIEHELLMAN", "DH");
        
        put("KeyPairGenerator.GOST3410", PROVIDER_PACKAGE_NAME+".JDKKeyPairGenerator$GOST3410");
        put("Alg.Alias.KeyPairGenerator.GOST-3410", "GOST3410");
        put("Alg.Alias.KeyPairGenerator.GOST-3410-94", "GOST3410");

        //
        // key factories
        //
        put("KeyFactory.RSA", PROVIDER_PACKAGE_NAME+".JDKKeyFactory$RSA");
        put("KeyFactory.DH", PROVIDER_PACKAGE_NAME+".JDKKeyFactory$DH");
        put("KeyFactory.DSA", PROVIDER_PACKAGE_NAME+".JDKKeyFactory$DSA");
        put("KeyFactory.ELGAMAL", PROVIDER_PACKAGE_NAME+".JDKKeyFactory$ElGamal");
        put("KeyFactory.ElGamal", PROVIDER_PACKAGE_NAME+".JDKKeyFactory$ElGamal");

        put("KeyFactory.X.509", PROVIDER_PACKAGE_NAME+".JDKKeyFactory$X509");
        
        put("Alg.Alias.KeyFactory.1.2.840.113549.1.1.1", "RSA");
        put("Alg.Alias.KeyFactory.1.2.840.10040.4.1", "DSA");

        put("Alg.Alias.KeyFactory.DIFFIEHELLMAN", "DH");

        put("KeyFactory.GOST3410", PROVIDER_PACKAGE_NAME+".JDKKeyFactory$GOST3410");
        put("Alg.Alias.KeyFactory.GOST-3410", "GOST3410");
        put("Alg.Alias.KeyFactory.GOST-3410-94", "GOST3410");
        put("Alg.Alias.KeyFactory." + CryptoProObjectIdentifiers.gostR3410_94, "GOST3410");

        //
        // Algorithm parameters
        //
        put("AlgorithmParameters.DES", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$IVAlgorithmParameters");
        put("Alg.Alias.AlgorithmParameters." + OIWObjectIdentifiers.desCBC, "DES");
        put("AlgorithmParameters.DESEDE", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$IVAlgorithmParameters");
        put("AlgorithmParameters." + PKCSObjectIdentifiers.des_EDE3_CBC, PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$IVAlgorithmParameters");
        put("AlgorithmParameters.RC2", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$RC2AlgorithmParameters");
        put("AlgorithmParameters.1.2.840.113549.3.2", PROVIDER_PACKAGE_NAME+".JDKAlgorithmParameters$RC2AlgorithmParameters");
        
        //
        // secret key factories.
        //
        put("SecretKeyFactory.DES", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$DES");
        put("SecretKeyFactory.PBEWITHMD2ANDDES", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithMD2AndDES");

        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, "PBEWITHMD2ANDDES");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC, "PBEWITHMD2ANDRC2");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, "PBEWITHMD5ANDDES");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC, "PBEWITHMD5ANDDES");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, "PBEWITHSHA1ANDDES");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC, "PBEWITHSHA1ANDRC2");

        put("SecretKeyFactory.PBEWITHMD2ANDRC2", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithMD2AndRC2");
        put("SecretKeyFactory.PBEWITHMD5ANDDES", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithMD5AndDES");
        put("SecretKeyFactory.PBEWITHMD5ANDRC2", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithMD5AndRC2");
        put("SecretKeyFactory.PBEWITHSHA1ANDDES", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHA1AndDES");
        put("SecretKeyFactory.PBEWITHSHA1ANDRC2", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHA1AndRC2");
        put("SecretKeyFactory.PBEWITHSHAAND3-KEYTRIPLEDES-CBC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAndDES3Key");
        put("SecretKeyFactory.PBEWITHSHAAND2-KEYTRIPLEDES-CBC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAndDES2Key");
        put("SecretKeyFactory.PBEWITHSHAAND128BITRC4", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAnd128BitRC4");
        put("SecretKeyFactory.PBEWITHSHAAND40BITRC4", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAnd40BitRC4");
        put("SecretKeyFactory.PBEWITHSHAAND128BITRC2-CBC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAnd128BitRC2");
        put("SecretKeyFactory.PBEWITHSHAAND40BITRC2-CBC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAnd40BitRC2");
        put("SecretKeyFactory.PBEWITHSHAANDTWOFISH-CBC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAndTwofish");
        put("SecretKeyFactory.PBEWITHHMACRIPEMD160", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithRIPEMD160");
        put("SecretKeyFactory.PBEWITHHMACSHA1", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHA");
        put("SecretKeyFactory.PBEWITHHMACTIGER", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithTiger");
        
        put("SecretKeyFactory.PBEWITHMD5AND128BITAES-CBC-OPENSSL", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithMD5And128BitAESCBCOpenSSL");
        put("SecretKeyFactory.PBEWITHMD5AND192BITAES-CBC-OPENSSL", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithMD5And192BitAESCBCOpenSSL");
        put("SecretKeyFactory.PBEWITHMD5AND256BITAES-CBC-OPENSSL", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithMD5And256BitAESCBCOpenSSL");

        put("Alg.Alias.SecretKeyFactory.PBE", "PBE/PKCS5");

        put("Alg.Alias.SecretKeyFactory.BROKENPBEWITHMD5ANDDES", "PBE/PKCS5");
        put("Alg.Alias.SecretKeyFactory.BROKENPBEWITHSHA1ANDDES", "PBE/PKCS5");
        put("Alg.Alias.SecretKeyFactory.OLDPBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBE/PKCS12");
        put("Alg.Alias.SecretKeyFactory.BROKENPBEWITHSHAAND3-KEYTRIPLEDES-CBC", "PBE/PKCS12");
        put("Alg.Alias.SecretKeyFactory.BROKENPBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PBE/PKCS12");
        put("Alg.Alias.SecretKeyFactory.OLDPBEWITHSHAANDTWOFISH-CBC", "PBE/PKCS12");

        put("Alg.Alias.SecretKeyFactory.PBEWITHMD2ANDDES-CBC", "PBEWITHMD2ANDDES");
        put("Alg.Alias.SecretKeyFactory.PBEWITHMD2ANDRC2-CBC", "PBEWITHMD2ANDRC2");
        put("Alg.Alias.SecretKeyFactory.PBEWITHMD5ANDDES-CBC", "PBEWITHMD5ANDDES");
        put("Alg.Alias.SecretKeyFactory.PBEWITHMD5ANDRC2-CBC", "PBEWITHMD5ANDRC2");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1ANDDES-CBC", "PBEWITHSHA1ANDDES");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1ANDRC2-CBC", "PBEWITHSHA1ANDRC2");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC, "PBEWITHMD2ANDDES");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC, "PBEWITHMD2ANDRC2");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC, "PBEWITHMD5ANDDES");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC, "PBEWITHMD5ANDRC2");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC, "PBEWITHSHA1ANDDES");
        put("Alg.Alias.SecretKeyFactory." + PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC, "PBEWITHSHA1ANDRC2");

        put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.1", "PBEWITHSHAAND128BITRC4");
        put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.2", "PBEWITHSHAAND40BITRC4");
        put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.3", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
        put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.4", "PBEWITHSHAAND2-KEYTRIPLEDES-CBC");
        put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.5", "PBEWITHSHAAND128BITRC2-CBC");
        put("Alg.Alias.SecretKeyFactory.1.2.840.113549.1.12.1.6", "PBEWITHSHAAND40BITRC2-CBC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHHMACSHA", "PBEWITHHMACSHA1");
        put("Alg.Alias.SecretKeyFactory.1.3.14.3.2.26", "PBEWITHHMACSHA1");
        put("Alg.Alias.SecretKeyFactory.PBEWithSHAAnd3KeyTripleDES", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC");
        
        put("SecretKeyFactory.PBEWITHSHAAND128BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAnd128BitAESBC");
        put("SecretKeyFactory.PBEWITHSHAAND192BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAnd192BitAESBC");
        put("SecretKeyFactory.PBEWITHSHAAND256BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHAAnd256BitAESBC");
        put("SecretKeyFactory.PBEWITHSHA256AND128BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHA256And128BitAESBC");
        put("SecretKeyFactory.PBEWITHSHA256AND192BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHA256And192BitAESBC");
        put("SecretKeyFactory.PBEWITHSHA256AND256BITAES-CBC-BC", PROVIDER_PACKAGE_NAME+".JCESecretKeyFactory$PBEWithSHA256And256BitAESBC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND128BITAES-CBC-BC","PBEWITHSHAAND128BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND192BITAES-CBC-BC","PBEWITHSHAAND192BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA1AND256BITAES-CBC-BC","PBEWITHSHAAND256BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND128BITAES-CBC-BC","PBEWITHSHAAND128BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND192BITAES-CBC-BC","PBEWITHSHAAND192BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-1AND256BITAES-CBC-BC","PBEWITHSHAAND256BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND128BITAES-CBC-BC","PBEWITHSHA256AND128BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND192BITAES-CBC-BC","PBEWITHSHA256AND192BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory.PBEWITHSHA-256AND256BITAES-CBC-BC","PBEWITHSHA256AND256BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes128_cbc.getId(), "PBEWITHSHAAND128BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes192_cbc.getId(), "PBEWITHSHAAND192BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha1_pkcs12_aes256_cbc.getId(), "PBEWITHSHAAND256BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes128_cbc.getId(), "PBEWITHSHA256AND128BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes192_cbc.getId(), "PBEWITHSHA256AND192BITAES-CBC-BC");
        put("Alg.Alias.SecretKeyFactory." + BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc.getId(), "PBEWITHSHA256AND256BITAES-CBC-BC");

        addMacAlgorithms();

        addMessageDigestAlgorithms();

        addSignatureAlgorithms();

    // Certification Path API
        put("CertPathValidator.RFC3281", PROVIDER_PACKAGE_NAME+".PKIXAttrCertPathValidatorSpi");
        put("CertPathBuilder.RFC3281", PROVIDER_PACKAGE_NAME+".PKIXAttrCertPathBuilderSpi");
        put("CertPathValidator.RFC3280", PROVIDER_PACKAGE_NAME+".PKIXCertPathValidatorSpi");
        put("CertPathBuilder.RFC3280", PROVIDER_PACKAGE_NAME+".PKIXCertPathBuilderSpi");
        put("CertPathValidator.PKIX", PROVIDER_PACKAGE_NAME+".PKIXCertPathValidatorSpi");
        put("CertPathBuilder.PKIX", PROVIDER_PACKAGE_NAME+".PKIXCertPathBuilderSpi");
        put("CertStore.Collection", PROVIDER_PACKAGE_NAME+".CertStoreCollectionSpi");
        put("CertStore.LDAP", PROVIDER_PACKAGE_NAME+".X509LDAPCertStoreSpi");
        put("CertStore.Multi", PROVIDER_PACKAGE_NAME+".MultiCertStoreSpi");
        put("Alg.Alias.CertStore.X509LDAP", "LDAP");
    }

    private void loadAlgorithms(String packageName, String[] names)
    {
        for (int i = 0; i != names.length; i++)
        {
            Class clazz = null;
            try
            {
                ClassLoader loader = this.getClass().getClassLoader();

                if (loader != null)
                {
                    clazz = loader.loadClass(packageName + names[i] + "$Mappings");
                }
                else
                {
                    clazz = Class.forName(packageName + names[i] + "$Mappings");
                }
            }
            catch (ClassNotFoundException e)
            {
                // ignore
            }

            if (clazz != null)
            {
                try
                {
                    addMappings((Map)clazz.newInstance());
                }
                catch (Exception e)
                {   // this should never ever happen!!
                    throw new InternalError("cannot create instance of "
                        + packageName + names[i] + "$Mappings : " + e);
                }
            }
        }
    }

    private void addMappings(Map mappings)
    {
        // can't use putAll due to JDK 1.1
        for (Iterator it = mappings.keySet().iterator(); it.hasNext();)
        {
            Object key = it.next();

            if (containsKey(key))
            {
                throw new IllegalStateException("duplicate provider key (" + key + ") found in " + mappings.getClass().getName());
            }
            put(key, mappings.get(key));
        }
    }

    //
    // macs
    //
    private void addMacAlgorithms()
    {
        put("Mac.DESMAC", PROVIDER_PACKAGE_NAME+".JCEMac$DES");
        put("Alg.Alias.Mac.DES", "DESMAC");
        put("Mac.DESMAC/CFB8", PROVIDER_PACKAGE_NAME+".JCEMac$DESCFB8");
        put("Alg.Alias.Mac.DES/CFB8", "DESMAC/CFB8");

        put("Mac.DESWITHISO9797", PROVIDER_PACKAGE_NAME+".JCEMac$DES9797Alg3");
        put("Alg.Alias.Mac.DESISO9797MAC", "DESWITHISO9797");

        put("Mac.ISO9797ALG3MAC", PROVIDER_PACKAGE_NAME+".JCEMac$DES9797Alg3");
        put("Alg.Alias.Mac.ISO9797ALG3", "ISO9797ALG3MAC");
        put("Mac.ISO9797ALG3WITHISO7816-4PADDING", PROVIDER_PACKAGE_NAME+".JCEMac$DES9797Alg3with7816d4");
        put("Alg.Alias.Mac.ISO9797ALG3MACWITHISO7816-4PADDING", "ISO9797ALG3WITHISO7816-4PADDING");

        put("Mac.RC2MAC", PROVIDER_PACKAGE_NAME+".JCEMac$RC2");
        put("Alg.Alias.Mac.RC2", "RC2MAC");
        put("Mac.RC2MAC/CFB8", PROVIDER_PACKAGE_NAME+".JCEMac$RC2CFB8");
        put("Alg.Alias.Mac.RC2/CFB8", "RC2MAC/CFB8");


        put("Mac.GOST28147MAC", PROVIDER_PACKAGE_NAME+".JCEMac$GOST28147");
        put("Alg.Alias.Mac.GOST28147", "GOST28147MAC");

        put("Mac.OLDHMACSHA384", PROVIDER_PACKAGE_NAME+".JCEMac$OldSHA384");

        put("Mac.OLDHMACSHA512", PROVIDER_PACKAGE_NAME+".JCEMac$OldSHA512");

        addHMACAlgorithm("MD2", PROVIDER_PACKAGE_NAME+".JCEMac$MD2", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$MD2HMAC");
        addHMACAlgorithm("MD4", PROVIDER_PACKAGE_NAME+".JCEMac$MD4", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$MD4HMAC");
        addHMACAlgorithm("MD5", PROVIDER_PACKAGE_NAME+".JCEMac$MD5", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$MD5HMAC");
        addHMACAlias("MD5", IANAObjectIdentifiers.hmacMD5);

        addHMACAlgorithm("SHA1", PROVIDER_PACKAGE_NAME+".JCEMac$SHA1", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$HMACSHA1");
        addHMACAlias("SHA1", PKCSObjectIdentifiers.id_hmacWithSHA1);
        addHMACAlias("SHA1", IANAObjectIdentifiers.hmacSHA1);
        addHMACAlgorithm("SHA224", PROVIDER_PACKAGE_NAME+".JCEMac$SHA224", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$HMACSHA224");
        addHMACAlias("SHA224", PKCSObjectIdentifiers.id_hmacWithSHA224);
        addHMACAlgorithm("SHA256", PROVIDER_PACKAGE_NAME+".JCEMac$SHA256", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$HMACSHA256");
        addHMACAlias("SHA256", PKCSObjectIdentifiers.id_hmacWithSHA256);
        addHMACAlgorithm("SHA384", PROVIDER_PACKAGE_NAME+".JCEMac$SHA384", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$HMACSHA384");
        addHMACAlias("SHA384", PKCSObjectIdentifiers.id_hmacWithSHA384);
        addHMACAlgorithm("SHA512", PROVIDER_PACKAGE_NAME+".JCEMac$SHA512", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$HMACSHA512");
        addHMACAlias("SHA512", PKCSObjectIdentifiers.id_hmacWithSHA512);

        addHMACAlgorithm("RIPEMD128", PROVIDER_PACKAGE_NAME+".JCEMac$RIPEMD128", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$RIPEMD128HMAC");
        addHMACAlgorithm("RIPEMD160", PROVIDER_PACKAGE_NAME+".JCEMac$RIPEMD160", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$RIPEMD160HMAC");
        addHMACAlias("RIPEMD160", IANAObjectIdentifiers.hmacRIPEMD160);

        addHMACAlgorithm("TIGER", PROVIDER_PACKAGE_NAME+".JCEMac$Tiger", PROVIDER_PACKAGE_NAME+".JCEKeyGenerator$HMACTIGER");
        addHMACAlias("TIGER", IANAObjectIdentifiers.hmacTIGER);

        put("Mac.PBEWITHHMACSHA", PROVIDER_PACKAGE_NAME+".JCEMac$PBEWithSHA");
        put("Mac.PBEWITHHMACSHA1", PROVIDER_PACKAGE_NAME+".JCEMac$PBEWithSHA");
        put("Mac.PBEWITHHMACRIPEMD160", PROVIDER_PACKAGE_NAME+".JCEMac$PBEWithRIPEMD160");
        put("Alg.Alias.Mac.1.3.14.3.2.26", "PBEWITHHMACSHA");
    }

    private void addHMACAlgorithm(
        String algorithm,
        String algorithmClassName,
        String keyGeneratorClassName)
    {
        String mainName = "HMAC" + algorithm;

        put("Mac." + mainName, algorithmClassName);
        put("Alg.Alias.Mac.HMAC-" + algorithm, mainName);
        put("Alg.Alias.Mac.HMAC/" + algorithm, mainName);
        put("KeyGenerator." + mainName, keyGeneratorClassName);
        put("Alg.Alias.KeyGenerator.HMAC-" + algorithm, mainName);
        put("Alg.Alias.KeyGenerator.HMAC/" + algorithm, mainName);
    }

    private void addHMACAlias(
        String              algorithm,
        DERObjectIdentifier oid)
    {
        String mainName = "HMAC" + algorithm;

        put("Alg.Alias.Mac." + oid, mainName);
        put("Alg.Alias.KeyGenerator." + oid, mainName);
    }

    //
    // message digests
    //
    private void addMessageDigestAlgorithms()
    {
        put("MessageDigest.SHA-1", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$SHA1");
        put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
        put("Alg.Alias.MessageDigest.SHA", "SHA-1");
        put("Alg.Alias.MessageDigest." + OIWObjectIdentifiers.idSHA1, "SHA-1");
        put("MessageDigest.SHA-224", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$SHA224");
        put("Alg.Alias.MessageDigest.SHA224", "SHA-224");
        put("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha224, "SHA-224");
        put("MessageDigest.SHA-256", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$SHA256");
        put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        put("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha256, "SHA-256");
        put("MessageDigest.SHA-384", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$SHA384");
        put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        put("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha384, "SHA-384");
        put("MessageDigest.SHA-512", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$SHA512");
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");
        put("Alg.Alias.MessageDigest." + NISTObjectIdentifiers.id_sha512, "SHA-512");
        
        put("MessageDigest.MD2", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$MD2");
        put("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers.md2, "MD2");
        put("MessageDigest.MD4", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$MD4");
        put("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers.md4, "MD4");
        put("MessageDigest.MD5", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$MD5");
        put("Alg.Alias.MessageDigest." + PKCSObjectIdentifiers.md5, "MD5");
        put("MessageDigest.RIPEMD128", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$RIPEMD128");
        put("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        put("MessageDigest.RIPEMD160", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$RIPEMD160");
        put("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        put("MessageDigest.RIPEMD256", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$RIPEMD256");
        put("Alg.Alias.MessageDigest." + TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
        put("MessageDigest.RIPEMD320", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$RIPEMD320");
        put("MessageDigest.Tiger", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$Tiger");
        
        put("MessageDigest.WHIRLPOOL", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$Whirlpool");
        
        put("MessageDigest.GOST3411", PROVIDER_PACKAGE_NAME+".JDKMessageDigest$GOST3411");
        put("Alg.Alias.MessageDigest.GOST", "GOST3411");
        put("Alg.Alias.MessageDigest.GOST-3411", "GOST3411");
        put("Alg.Alias.MessageDigest." + CryptoProObjectIdentifiers.gostR3411, "GOST3411");
    }
    
    //
    // signature algorithms.
    //
    private void addSignatureAlgorithms()
    {
        put("Signature.MD2WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$MD2WithRSAEncryption");
        put("Signature.MD4WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$MD4WithRSAEncryption");
        put("Signature.MD5WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$MD5WithRSAEncryption");
        put("Signature.SHA1WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$SHA1WithRSAEncryption");
        put("Signature.SHA224WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$SHA224WithRSAEncryption");
        put("Signature.SHA256WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$SHA256WithRSAEncryption");
        put("Signature.SHA384WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$SHA384WithRSAEncryption");
        put("Signature.SHA512WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$SHA512WithRSAEncryption");
        put("Signature.RIPEMD160WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$RIPEMD160WithRSAEncryption");
        put("Signature.RIPEMD128WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$RIPEMD128WithRSAEncryption");
        put("Signature.RIPEMD256WithRSAEncryption", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$RIPEMD256WithRSAEncryption");
        put("Signature.DSA", PROVIDER_PACKAGE_NAME+".JDKDSASigner$stdDSA");
        put("Signature.NONEWITHDSA", PROVIDER_PACKAGE_NAME+".JDKDSASigner$noneDSA");
        put("Signature.SHA1withRSA/ISO9796-2", PROVIDER_PACKAGE_NAME+".JDKISOSignature$SHA1WithRSAEncryption");
        put("Signature.MD5withRSA/ISO9796-2", PROVIDER_PACKAGE_NAME+".JDKISOSignature$MD5WithRSAEncryption");
        put("Signature.RIPEMD160withRSA/ISO9796-2", PROVIDER_PACKAGE_NAME+".JDKISOSignature$RIPEMD160WithRSAEncryption");

        put("Signature.RSASSA-PSS", PROVIDER_PACKAGE_NAME+".JDKPSSSigner$PSSwithRSA");
        put("Signature." + PKCSObjectIdentifiers.id_RSASSA_PSS, PROVIDER_PACKAGE_NAME+".JDKPSSSigner$PSSwithRSA");
        put("Signature.SHA1withRSA/PSS", PROVIDER_PACKAGE_NAME+".JDKPSSSigner$SHA1withRSA");
        put("Signature.SHA224withRSA/PSS", PROVIDER_PACKAGE_NAME+".JDKPSSSigner$SHA224withRSA");
        put("Signature.SHA256withRSA/PSS", PROVIDER_PACKAGE_NAME+".JDKPSSSigner$SHA256withRSA");
        put("Signature.SHA384withRSA/PSS", PROVIDER_PACKAGE_NAME+".JDKPSSSigner$SHA384withRSA");
        put("Signature.SHA512withRSA/PSS", PROVIDER_PACKAGE_NAME+".JDKPSSSigner$SHA512withRSA");

        put("Signature.RSA", PROVIDER_PACKAGE_NAME+".JDKDigestSignature$noneRSA");
        put("Signature.RAWRSASSA-PSS", PROVIDER_PACKAGE_NAME+".JDKPSSSigner$nonePSS");

        put("Alg.Alias.Signature.RAWDSA", "NONEWITHDSA");

        put("Alg.Alias.Signature.RAWRSA", "RSA");
        put("Alg.Alias.Signature.NONEWITHRSA", "RSA");
        put("Alg.Alias.Signature.RAWRSAPSS", "RAWRSASSA-PSS");
        put("Alg.Alias.Signature.NONEWITHRSAPSS", "RAWRSASSA-PSS");
        put("Alg.Alias.Signature.NONEWITHRSASSA-PSS", "RAWRSASSA-PSS");

        put("Alg.Alias.Signature.RSAPSS", "RSASSA-PSS");

        put("Alg.Alias.Signature.SHA1withRSAandMGF1", "SHA1withRSA/PSS");
        put("Alg.Alias.Signature.SHA224withRSAandMGF1", "SHA224withRSA/PSS");
        put("Alg.Alias.Signature.SHA256withRSAandMGF1", "SHA256withRSA/PSS");
        put("Alg.Alias.Signature.SHA384withRSAandMGF1", "SHA384withRSA/PSS");
        put("Alg.Alias.Signature.SHA512withRSAandMGF1", "SHA512withRSA/PSS");
        
        put("Alg.Alias.Signature.MD2withRSAEncryption", "MD2WithRSAEncryption");
        put("Alg.Alias.Signature.MD4withRSAEncryption", "MD4WithRSAEncryption");
        put("Alg.Alias.Signature.MD5withRSAEncryption", "MD5WithRSAEncryption");
        put("Alg.Alias.Signature.SHA1withRSAEncryption", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature.SHA224withRSAEncryption", "SHA224WithRSAEncryption");

        put("Alg.Alias.Signature.SHA256withRSAEncryption", "SHA256WithRSAEncryption");
        put("Alg.Alias.Signature.SHA384withRSAEncryption", "SHA384WithRSAEncryption");
        put("Alg.Alias.Signature.SHA512withRSAEncryption", "SHA512WithRSAEncryption");

        put("Alg.Alias.Signature.SHA256WithRSAEncryption", "SHA256WithRSAEncryption");
        put("Alg.Alias.Signature.SHA384WithRSAEncryption", "SHA384WithRSAEncryption");
        put("Alg.Alias.Signature.SHA512WithRSAEncryption", "SHA512WithRSAEncryption");

        put("Alg.Alias.Signature.SHA256WITHRSAENCRYPTION", "SHA256WithRSAEncryption");
        put("Alg.Alias.Signature.SHA384WITHRSAENCRYPTION", "SHA384WithRSAEncryption");
        put("Alg.Alias.Signature.SHA512WITHRSAENCRYPTION", "SHA512WithRSAEncryption");

        put("Alg.Alias.Signature.RIPEMD160withRSAEncryption", "RIPEMD160WithRSAEncryption");

        put("Alg.Alias.Signature." + PKCSObjectIdentifiers.md2WithRSAEncryption, "MD2WithRSAEncryption");
        put("Alg.Alias.Signature.MD2WithRSA", "MD2WithRSAEncryption");
        put("Alg.Alias.Signature.MD2withRSA", "MD2WithRSAEncryption");
        put("Alg.Alias.Signature.MD2/RSA", "MD2WithRSAEncryption");
        put("Alg.Alias.Signature.MD5WithRSA", "MD5WithRSAEncryption");
        put("Alg.Alias.Signature.MD5withRSA", "MD5WithRSAEncryption");
        put("Alg.Alias.Signature.MD5/RSA", "MD5WithRSAEncryption");
        put("Alg.Alias.Signature." + PKCSObjectIdentifiers.md5WithRSAEncryption, "MD5WithRSAEncryption");
        put("Alg.Alias.Signature.MD4WithRSA", "MD4WithRSAEncryption");
        put("Alg.Alias.Signature.MD4withRSA", "MD4WithRSAEncryption");
        put("Alg.Alias.Signature.MD4/RSA", "MD4WithRSAEncryption");
        put("Alg.Alias.Signature." + PKCSObjectIdentifiers.md4WithRSAEncryption, "MD4WithRSAEncryption");
        put("Alg.Alias.Signature.SHA1WithRSA", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature.SHA1withRSA", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature.SHA224WithRSA", "SHA224WithRSAEncryption");
        put("Alg.Alias.Signature.SHA224withRSA", "SHA224WithRSAEncryption");
        put("Alg.Alias.Signature.SHA256WithRSA", "SHA256WithRSAEncryption");
        put("Alg.Alias.Signature.SHA256withRSA", "SHA256WithRSAEncryption");
        put("Alg.Alias.Signature.SHA384WithRSA", "SHA384WithRSAEncryption");
        put("Alg.Alias.Signature.SHA384withRSA", "SHA384WithRSAEncryption");
        put("Alg.Alias.Signature.SHA512WithRSA", "SHA512WithRSAEncryption");
        put("Alg.Alias.Signature.SHA512withRSA", "SHA512WithRSAEncryption");
        put("Alg.Alias.Signature.SHA1/RSA", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature.SHA-1/RSA", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature." + PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature." + PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WithRSAEncryption");
        put("Alg.Alias.Signature." + PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WithRSAEncryption");
        put("Alg.Alias.Signature." + PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WithRSAEncryption");
        put("Alg.Alias.Signature." + PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WithRSAEncryption");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.1", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.113549.1.1.5", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature.1.2.840.113549.2.5with1.2.840.113549.1.1.1", "MD5WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD160WithRSA", "RIPEMD160WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD160withRSA", "RIPEMD160WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD128WithRSA", "RIPEMD128WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD128withRSA", "RIPEMD128WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD256WithRSA", "RIPEMD256WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD256withRSA", "RIPEMD256WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD-160/RSA", "RIPEMD160WithRSAEncryption");
        put("Alg.Alias.Signature.RMD160withRSA", "RIPEMD160WithRSAEncryption");
        put("Alg.Alias.Signature.RMD160/RSA", "RIPEMD160WithRSAEncryption");
        put("Alg.Alias.Signature.1.3.36.3.3.1.2", "RIPEMD160WithRSAEncryption");
        put("Alg.Alias.Signature.1.3.36.3.3.1.3", "RIPEMD128WithRSAEncryption");
        put("Alg.Alias.Signature.1.3.36.3.3.1.4", "RIPEMD256WithRSAEncryption");
        put("Alg.Alias.Signature." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WithRSAEncryption");
        
        put("Alg.Alias.Signature.MD2WITHRSAENCRYPTION", "MD2WithRSAEncryption");
        put("Alg.Alias.Signature.MD5WITHRSAENCRYPTION", "MD5WithRSAEncryption");
        put("Alg.Alias.Signature.SHA1WITHRSAENCRYPTION", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD160WITHRSAENCRYPTION", "RIPEMD160WithRSAEncryption");

        put("Alg.Alias.Signature.MD5WITHRSA", "MD5WithRSAEncryption");
        put("Alg.Alias.Signature.SHA1WITHRSA", "SHA1WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD160WITHRSA", "RIPEMD160WithRSAEncryption");
        put("Alg.Alias.Signature.RMD160WITHRSA", "RIPEMD160WithRSAEncryption");
        put("Alg.Alias.Signature.RIPEMD160WITHRSA", "RIPEMD160WithRSAEncryption");

        addSignatureAlgorithm("SHA224", "DSA", PROVIDER_PACKAGE_NAME+".JDKDSASigner$dsa224", NISTObjectIdentifiers.dsa_with_sha224);
        addSignatureAlgorithm("SHA256", "DSA", PROVIDER_PACKAGE_NAME+".JDKDSASigner$dsa256", NISTObjectIdentifiers.dsa_with_sha256);
        addSignatureAlgorithm("SHA384", "DSA", PROVIDER_PACKAGE_NAME+".JDKDSASigner$dsa384", NISTObjectIdentifiers.dsa_with_sha384);
        addSignatureAlgorithm("SHA512", "DSA", PROVIDER_PACKAGE_NAME+".JDKDSASigner$dsa512", NISTObjectIdentifiers.dsa_with_sha512);

        put("Alg.Alias.Signature.SHA/DSA", "DSA");
        put("Alg.Alias.Signature.SHA1withDSA", "DSA");
        put("Alg.Alias.Signature.SHA1WITHDSA", "DSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.1", "DSA");
        put("Alg.Alias.Signature.1.3.14.3.2.26with1.2.840.10040.4.3", "DSA");
        put("Alg.Alias.Signature.DSAwithSHA1", "DSA");
        put("Alg.Alias.Signature.DSAWITHSHA1", "DSA");
        put("Alg.Alias.Signature.SHA1WithDSA", "DSA");
        put("Alg.Alias.Signature.DSAWithSHA1", "DSA");
        put("Alg.Alias.Signature.1.2.840.10040.4.3", "DSA");
        put("Alg.Alias.Signature.MD5WithRSA/ISO9796-2", "MD5withRSA/ISO9796-2");
        put("Alg.Alias.Signature.SHA1WithRSA/ISO9796-2", "SHA1withRSA/ISO9796-2");
        put("Alg.Alias.Signature.RIPEMD160WithRSA/ISO9796-2", "RIPEMD160withRSA/ISO9796-2");
        
        put("Signature.ECGOST3410", PROVIDER_PACKAGE_NAME+".JDKGOST3410Signer$ecgost3410");
        put("Alg.Alias.Signature.ECGOST-3410", "ECGOST3410");
        put("Alg.Alias.Signature.GOST-3410-2001", "ECGOST3410");
        put("Alg.Alias.Signature.GOST3411withECGOST3410", "ECGOST3410");
        put("Alg.Alias.Signature.GOST3411WITHECGOST3410", "ECGOST3410");
        put("Alg.Alias.Signature.GOST3411WithECGOST3410", "ECGOST3410");
        put("Alg.Alias.Signature." + CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "ECGOST3410");
        
        put("Signature.GOST3410", PROVIDER_PACKAGE_NAME+".JDKGOST3410Signer$gost3410");
        put("Alg.Alias.Signature.GOST-3410", "GOST3410");
        put("Alg.Alias.Signature.GOST-3410-94", "GOST3410");
        put("Alg.Alias.Signature.GOST3411withGOST3410", "GOST3410");
        put("Alg.Alias.Signature.GOST3411WITHGOST3410", "GOST3410");
        put("Alg.Alias.Signature.GOST3411WithGOST3410", "GOST3410");
        put("Alg.Alias.Signature." + CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3410");
    }

    private void addSignatureAlgorithm(
        String digest,
        String algorithm,
        String className,
        DERObjectIdentifier oid)
    {
        String mainName = digest + "WITH" + algorithm;
        String jdk11Variation1 = digest + "with" + algorithm;
        String jdk11Variation2 = digest + "With" + algorithm;
        String alias = digest + "/" + algorithm;

        put("Signature." + mainName, className);
        put("Alg.Alias.Signature." + jdk11Variation1, mainName);
        put("Alg.Alias.Signature." + jdk11Variation2, mainName);
        put("Alg.Alias.Signature." + alias, mainName);
        put("Alg.Alias.Signature." + oid, mainName);
        put("Alg.Alias.Signature.OID." + oid, mainName);
    }

    public void setParameter(String parameterName, Object parameter)
    {
        ProviderUtil.setParameter(parameterName, parameter);
    }
}
