package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class CertificatePolicies
    extends ASN1Object
{
    static final ASN1ObjectIdentifier anyPolicy = new ASN1ObjectIdentifier("2.5.29.32.0");

    Vector policies = new Vector();

/**
 * @deprecated use an ASN1Sequence of PolicyInformation
 */
    public static CertificatePolicies getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

/**
 * @deprecated use an ASN1Sequence of PolicyInformation
 */
    public static CertificatePolicies getInstance(
        Object  obj)
    {
        if (obj instanceof CertificatePolicies)
        {
            return (CertificatePolicies)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new CertificatePolicies((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

/**
 * @deprecated use an ASN1Sequence of PolicyInformation
 */
    public CertificatePolicies(
        ASN1Sequence   seq)
    {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements())
        {
            ASN1Sequence s = ASN1Sequence.getInstance(e.nextElement());
            policies.addElement(s.getObjectAt(0));
        }
        // For now we just don't handle PolicyQualifiers
    }

    /**
     * create a certificate policy with the given OID.
     * @deprecated use an ASN1Sequence of PolicyInformation
     */
    public CertificatePolicies(
        ASN1ObjectIdentifier p)
    {
        policies.addElement(p);
    }

    /**
     * create a certificate policy with the policy given by the OID represented
     * by the string p.
     * @deprecated use an ASN1Sequence of PolicyInformation
     */
    public CertificatePolicies(
        String p)
    {
        this(new ASN1ObjectIdentifier(p));
    }

    public void addPolicy(
        String p)
    {
        policies.addElement(new ASN1ObjectIdentifier(p));
    }

    public String getPolicy(int nr)
    {
        if (policies.size() > nr)
        {
            return ((ASN1ObjectIdentifier)policies.elementAt(nr)).getId();
        }
        
        return null;
    }

    /**
     * <pre>
     * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
     *
     * PolicyInformation ::= SEQUENCE {
     *   policyIdentifier   CertPolicyId,
     *   policyQualifiers   SEQUENCE SIZE (1..MAX) OF
     *                           PolicyQualifierInfo OPTIONAL }
     *
     * CertPolicyId ::= OBJECT IDENTIFIER
     *
     * PolicyQualifierInfo ::= SEQUENCE {
     *   policyQualifierId  PolicyQualifierId,
     *   qualifier          ANY DEFINED BY policyQualifierId }
     *
     * PolicyQualifierId ::=
     *   OBJECT IDENTIFIER (id-qt-cps | id-qt-unotice)
     * </pre>
     * @deprecated use an ASN1Sequence of PolicyInformation
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        // We only do policyIdentifier yet...
        for (int i=0;i<policies.size();i++)
        {
            v.add(new DERSequence((ASN1ObjectIdentifier)policies.elementAt(i)));
        }

        return new DERSequence(v);
    }

    public String toString()
    {
        String p = null;
        for (int i=0;i<policies.size();i++)
        {
            if (p != null)
            {
                p += ", ";
            }
            p += ((ASN1ObjectIdentifier)policies.elementAt(i)).getId();
        }
        return "CertificatePolicies: "+p;
    }
}
