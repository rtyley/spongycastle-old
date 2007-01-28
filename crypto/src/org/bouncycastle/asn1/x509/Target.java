package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Target structure used in target information extension for attribute
 * certificates from RFC 3281.
 * 
 * <pre>
 *     Target  ::= CHOICE {
 *       targetName          [0] GeneralName,
 *       targetGroup         [1] GeneralName,
 *       targetCert          [2] TargetCert
 *     }
 * </pre>
 * 
 * <p>
 * The targetCert field is currently not supported and must not be used
 * according to RFC 3281.
 */
public class Target
    extends ASN1Encodable
    implements ASN1Choice
{

    private GeneralName targetName;

    private GeneralName targetGroup;

    /**
     * Creates an instance of a Target from the given object.
     * <p>
     * <code>obj</code> can be a Target or a {@link ASN1TaggedObject}
     * 
     * @param obj The object.
     * @return A Target instance.
     * @throws IllegalArgumentException if the given object cannot be
     *             interpreted as Target.
     */
    public static Target getInstance(Object obj)
    {
        if (obj instanceof Target)
        {
            return (Target) obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new Target((ASN1TaggedObject) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: "
            + obj.getClass());
    }

    /**
     * Constructor from ASN1TaggedObject.
     * 
     * @param tagObj The tagged object.
     * @throws IllegalArgumentException if the encoding is wrong.
     */
    public Target(ASN1TaggedObject tagObj)
    {
        switch (tagObj.getTagNo())
        {
        case 0:     // GeneralName is already a choice so explicit
            targetName = GeneralName.getInstance(tagObj, true);
            break;
        case 1:
            targetGroup = GeneralName.getInstance(tagObj, true);
            break;
        default:
            throw new IllegalArgumentException("unknown tag: " + tagObj.getTagNo());
        }
    }

    /**
     * Constructor from given details.
     * <p>
     * Exactly one of the parameters must be not <code>null</code>.
     * 
     * @param targetName The allowed target name.
     * 
     * @param targetGroup The allowed target group.
     * @throws IllegalArgumentException if both parameters are <code>null</code>.
     */
    public Target(GeneralName targetName, GeneralName targetGroup)
    {
        if (targetGroup == null && targetName == null)
        {
            throw new IllegalArgumentException(
                "All parameters are null for Target.");
        }
        if (targetName != null)
        {
            this.targetName = targetName;
        }
        if (targetGroup != null)
        {
            this.targetGroup = targetGroup;
        }
    }

    /**
     * @return Returns the targetGroup.
     */
    public GeneralName getTargetGroup()
    {
        return targetGroup;
    }

    /**
     * @return Returns the targetName.
     */
    public GeneralName getTargetName()
    {
        return targetName;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * 
     * Returns:
     * 
     * <pre>
     *     Target  ::= CHOICE {
     *       targetName          [0] GeneralName,
     *       targetGroup         [1] GeneralName,
     *       targetCert          [2] TargetCert
     *     }
     * </pre>
     * 
     * @return a DERObject
     */
    public DERObject toASN1Object()
    {
        // GeneralName is a choice already so most be explicitly tagged
        if (targetName != null)
        {
            return new DERTaggedObject(true, 0, targetName);
        }
        else
        {
            return new DERTaggedObject(true, 1, targetGroup);
        }
    }
}
