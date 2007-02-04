package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

import java.util.Enumeration;
import java.util.Vector;

/**
 * Target information extension for attributes certificates according to RFC
 * 3281.
 * 
 * <pre>
 *           SEQUENCE OF Targets
 * </pre>
 * 
 */
public class TargetInformation
    extends ASN1Encodable
{

    private ASN1Sequence _seq;

    private Vector _targets;

    /**
     * Creates an instance of a TargetInformation from the given object.
     * <p>
     * <code>obj</code> can be a TargetInformation or a {@link ASN1Sequence}
     * 
     * @param obj The object.
     * @return A TargetInformation instance.
     * @throws IllegalArgumentException if the given object cannot be
     *             interpreted as TargetInformation.
     */
    public static TargetInformation getInstance(Object obj)
    {
        if (obj instanceof TargetInformation)
        {
            return (TargetInformation) obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new TargetInformation((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: "
            + obj.getClass());
    }

    /**
     * Constructor from a ASN1Sequence.
     * 
     * @param seq The ASN1Sequence.
     * @throws IllegalArgumentException if the sequence does not contain
     *             correctly encoded Targets elements.
     */
    private TargetInformation(ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();
        _targets = new Vector(seq.size());
        while (e.hasMoreElements())
        {
            _targets.addElement(Targets.getInstance(e.nextElement()));
        }
        _seq = seq;
    }

    /**
     * Returns the targets in this target information extension.
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
     * Constructs a target information from a single targets element. 
     * According to RFC 3281 only one targets element must be produced.
     * 
     * @param targets A Targets instance.
     */
    public TargetInformation(Targets targets)
    {
        _targets = new Vector(1);
        _targets.addElement(targets);
    }
    
    /**
     * According to RFC 3281 only one targets element must be produced. If
     * multiple targets are given in the constructor they are merged in
     * {@link #toASN1Object()} into one targets element.
     * <p>
     * The vector is copied.
     * 
     * @param targets A <code>Vector</code> with {@link Targets}.
     * @throws IllegalArgumentException if the vector does not consists of only
     *             Targets objects.
     */
    public TargetInformation(Vector targets)
    {
        Enumeration e = targets.elements();
        while (e.hasMoreElements())
        {
            Object o = e.nextElement();
            if (!(o instanceof Targets))
            {
                throw new IllegalArgumentException(
                    "Content of vector must be a Targets instance.");
            }
        }
        _targets = new Vector(targets.capacity());
        for (e = targets.elements(); e.hasMoreElements();)
        {
            _targets.addElement(e.nextElement());
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * 
     * Returns:
     * 
     * <pre>
     *          SEQUENCE OF Targets
     * </pre>
     * 
     * <p>
     * According to RFC 3281 only one targets element must be produced. If
     * multiple targets are given in the constructor they are merged into one
     * targets element. If this was produced from a
     * {@link org.bouncycastle.asn1.ASN1Sequence} the encoding is kept.
     * 
     * @return a DERObject
     */
    public DERObject toASN1Object()
    {
        if (_seq != null)
        {
            return _seq;
        }
        Vector targets = new Vector();
        // collect all target elements and use only one targets element
        for (Enumeration e = _targets.elements(); e.hasMoreElements();)
        {
            Targets t = (Targets)e.nextElement();
            for (Enumeration e2 = t.getTargets().elements(); e2.hasMoreElements();)
            {
                targets.addElement(e2.nextElement());
            }
        }
        return new DERSequence(new Targets(targets).toASN1Object());
    }
}
