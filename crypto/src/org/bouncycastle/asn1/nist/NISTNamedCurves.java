package org.bouncycastle.asn1.nist;

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.util.Strings;

/**
 * Utility class for fetching curves using their NIST names as published in FIPS-PUB 186-2
 */
public class NISTNamedCurves
{
    static final Hashtable objIds = new Hashtable();
    static final Hashtable curves = new Hashtable();
    static final Hashtable names = new Hashtable();

    static
    {
        objIds.put("B-571", SECObjectIdentifiers.sect571r1);
        objIds.put("B-409", SECObjectIdentifiers.sect409r1);  
        objIds.put("B-283", SECObjectIdentifiers.sect283r1);
        objIds.put("B-233", SECObjectIdentifiers.sect233r1);
        objIds.put("B-163", SECObjectIdentifiers.sect163r2);       
        objIds.put("P-521", SECObjectIdentifiers.secp521r1);       
        objIds.put("P-256", SECObjectIdentifiers.secp256r1);   
        objIds.put("P-224", SECObjectIdentifiers.secp224r1); 
        objIds.put("P-384", SECObjectIdentifiers.secp384r1); 

        names.put(SECObjectIdentifiers.sect571r1, "B-571"); 
        names.put(SECObjectIdentifiers.sect409r1, "B-409");  
        names.put(SECObjectIdentifiers.sect283r1, "B-283");
        names.put(SECObjectIdentifiers.sect233r1, "B-233");
        names.put(SECObjectIdentifiers.sect163r2, "B-163");       
        names.put(SECObjectIdentifiers.secp521r1, "P-521");       
        names.put(SECObjectIdentifiers.secp256r1, "P-256"); 
        names.put(SECObjectIdentifiers.secp224r1, "P-224");
        names.put(SECObjectIdentifiers.secp384r1, "P-384");

        curves.put(SECObjectIdentifiers.sect571r1, SECNamedCurves.getByName("sect571r1"));
        curves.put(SECObjectIdentifiers.sect409r1, SECNamedCurves.getByName("sect409r1")); 
        curves.put(SECObjectIdentifiers.sect283r1, SECNamedCurves.getByName("sect283r1")); 
        curves.put(SECObjectIdentifiers.sect233r1, SECNamedCurves.getByName("sect233r1")); 
        curves.put(SECObjectIdentifiers.sect163r2, SECNamedCurves.getByName("sect163r2"));       
        curves.put(SECObjectIdentifiers.secp521r1, SECNamedCurves.getByName("secp521r1")); 
        curves.put(SECObjectIdentifiers.secp256r1, SECNamedCurves.getByName("secp256r1"));
        curves.put(SECObjectIdentifiers.secp224r1, SECNamedCurves.getByName("secp224r1"));             
        curves.put(SECObjectIdentifiers.secp384r1, SECNamedCurves.getByName("secp384r1"));             
    }
    
    public static X9ECParameters getByName(
        String  name)
    {
        DERObjectIdentifier oid = (DERObjectIdentifier)objIds.get(Strings.toUpperCase(name));

        if (oid != null)
        {
            return (X9ECParameters)curves.get(oid);
        }

        return null;
    }

    /**
     * return the X9ECParameters object for the named curve represented by
     * the passed in object identifier. Null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     */
    public static X9ECParameters getByOID(
        DERObjectIdentifier  oid)
    {
        return (X9ECParameters)curves.get(oid);
    }

    /**
     * return the object identifier signified by the passed in name. Null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static DERObjectIdentifier getOID(
        String  name)
    {
        return (DERObjectIdentifier)objIds.get(name);
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static String getName(
        DERObjectIdentifier  oid)
    {
        return (String)names.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves
     * contained in this structure.
     */
    public static Enumeration getNames()
    {
        return objIds.keys();
    }
}
