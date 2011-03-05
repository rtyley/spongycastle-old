package org.spongycastle.jce;

import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X962NamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;

import java.util.Enumeration;
import java.util.Vector;

/**
 * a table of locally supported named curves.
 */
public class ECNamedCurveTable
{
    /**
     * return a parameter spec representing the passed in named
     * curve. The routine returns null if the curve is not present.
     * 
     * @param name the name of the curve requested
     * @return a parameter spec for the curve, null if it is not available.
     */
    public static ECNamedCurveParameterSpec getParameterSpec(
        String  name)
    {
        X9ECParameters  ecP = X962NamedCurves.getByName(name);
        if (ecP == null)
        {
            try
            {
                ecP = X962NamedCurves.getByOID(new DERObjectIdentifier(name));
            }
            catch (IllegalArgumentException e)
            {
                // ignore - not an oid
            }
        }
        
        if (ecP == null)
        {
            ecP = SECNamedCurves.getByName(name);
            if (ecP == null)
            {
                try
                {
                    ecP = SECNamedCurves.getByOID(new DERObjectIdentifier(name));
                }
                catch (IllegalArgumentException e)
                {
                    // ignore - not an oid
                }
            }
        }

        if (ecP == null)
        {
            ecP = TeleTrusTNamedCurves.getByName(name);
            if (ecP == null)
            {
                try
                {
                    ecP = TeleTrusTNamedCurves.getByOID(new DERObjectIdentifier(name));
                }
                catch (IllegalArgumentException e)
                {
                    // ignore - not an oid
                }
            }
        }

        if (ecP == null)
        {
            ecP = NISTNamedCurves.getByName(name);
        }
        
        if (ecP == null)
        {
            return null;
        }

        return new ECNamedCurveParameterSpec(
                                        name,
                                        ecP.getCurve(),
                                        ecP.getG(),
                                        ecP.getN(),
                                        ecP.getH(),
                                        ecP.getSeed());
    }

    /**
     * return an enumeration of the names of the available curves.
     *
     * @return an enumeration of the names of the available curves.
     */
    public static Enumeration getNames()
    {
        Vector v = new Vector();
        
        addEnumeration(v, X962NamedCurves.getNames());
        addEnumeration(v, SECNamedCurves.getNames());
        addEnumeration(v, NISTNamedCurves.getNames());
        addEnumeration(v, TeleTrusTNamedCurves.getNames());

        return v.elements();
    }

    private static void addEnumeration(
        Vector v, 
        Enumeration e)
    {
        while (e.hasMoreElements())
        {
            v.addElement(e.nextElement());
        }
    }
}
