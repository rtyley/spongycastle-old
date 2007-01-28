package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

import java.util.Enumeration;
import java.util.Vector;

/**
 * Targets structure used in target information extension for attribute
 * certificates from RFC 3281.
 * 
 * <pre>
 *            Targets ::= SEQUENCE OF Target
 *           
 *            Target  ::= CHOICE {
 *              targetName          [0] GeneralName,
 *              targetGroup         [1] GeneralName,
 *              targetCert          [2] TargetCert
 *            }
 *           
 *            TargetCert  ::= SEQUENCE {
 *              targetCertificate    IssuerSerial,
 *              targetName           GeneralName OPTIONAL,
 *              certDigestInfo       ObjectDigestInfo OPTIONAL
 *            }
 * </pre>
 * 
 * @see org.bouncycastle.asn1.x509.Target
 * @see org.bouncycastle.asn1.x509.TargetInformation
 */
public class Targets
    extends ASN1Encodable
{
    private Vector _targets;

    /**
     * Creates an instance of a Targets from the given object.
     * <p>
     * <code>obj</code> can be a Targets or a {@link ASN1Sequence}
     * 
     * @param obj The object.
     * @return A Targets instance.
     * @throws IllegalArgumentException if the given object cannot be
     *             interpreted as Target.
     */
    public static Targets getInstance(Object obj)
    {
        if (obj instanceof Targets)
        {
            return (Targets) obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new Targets((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: "
            + obj.getClass());
    }

    /**
     * Constructor from ASN1Sequence.
     * 
     * @param targets The ASN.1 SEQUENCE.
     * @throws IllegalArgumentException if the contents of the sequence are
     *             invalid.
     */
    public Targets(ASN1Sequence targets)
    {
        _targets = new Vector();
        // check contents
        Enumeration e = targets.getObjects();
        while (e.hasMoreElements())
        {
            _targets.addElement(Target.getInstance(e.nextElement()));
        }
    }

    /**
     * Constructor from given targets.
     * <p>
     * The vector is copied.
     * 
     * @param targets A <code>Vector</code> of {@link Target}s.
     * @see Target
     * @throws IllegalArgumentException if the vector contains not only Targets.
     */
    public Targets(Vector targets)
    {
        _targets = new Vector();
        for (Enumeration e = targets.elements(); e.hasMoreElements();)
        {
            Object o = e.nextElement();
            if (!(o instanceof Target))
            {
                throw new IllegalArgumentException(
                    "Content of vector must be a Target instance.");
            }
            _targets.addElement(o);
        }
    }

    /**
     * Returns the targets in a <code>Vector</code>.
     * <p>
     * The vector is cloned before it is returned.
     * 
     * @return Returns the targets.
     */
    public Vector getTargets()
    {
        Vector copy = new Vector(_targets.capacity());
        for (Enumeration e = _targets.elements(); e.hasMoreElements();)
        {
            copy.addElement(e.nextElement());
        }
        return copy;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * 
     * Returns:
     * 
     * <pre>
     *            Targets ::= SEQUENCE OF Target
     * </pre>
     * 
     * @return a DERObject
     */
    public DERObject toASN1Object()
    {
        DEREncodableVector vec = new DEREncodableVector();
        for (Enumeration e = _targets.elements(); e.hasMoreElements();)
        {
            Object o = e.nextElement();
            vec.add((DEREncodable) o);
        }
        return new DERSequence(vec);
    }
}
