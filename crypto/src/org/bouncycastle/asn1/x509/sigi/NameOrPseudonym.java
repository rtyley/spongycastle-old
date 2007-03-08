package org.bouncycastle.asn1.x509.sigi;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;

import java.util.Enumeration;
import java.util.Vector;

/**
 * Structure for a name or pseudonym.
 * 
 * <pre>
 *       NameOrPseudonym ::= CHOICE {
 *            surAndGivenName SEQUENCE {
 *              surName DirectoryString,
 *              givenName SEQUENCE OF DirectoryString 
 *         },
 *            pseudonym DirectoryString 
 *       }
 * </pre>
 * 
 * @see org.bouncycastle.asn1.x509.sigi.PersonalData
 * 
 */
public class NameOrPseudonym
    extends ASN1Encodable
    implements ASN1Choice
{
    private DirectoryString pseudonym;

    private DirectoryString surname = null;

    private Vector givenName = null;

    public static NameOrPseudonym getInstance(Object obj)
    {
        if (obj == null || obj instanceof NameOrPseudonym)
        {
            return (NameOrPseudonym)obj;
        }

        if (obj instanceof DERString)
        {
            return new NameOrPseudonym(DirectoryString.getInstance(obj));
        }

        if (obj instanceof ASN1Sequence)
        {
            return new NameOrPseudonym((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
            + obj.getClass().getName());
    }

    /**
     * Constructor from DERString.
     * <p/>
     * The sequence is of type NameOrPseudonym:
     * <p/>
     * <pre>
     *       NameOrPseudonym ::= CHOICE {
     *            surAndGivenName SEQUENCE {
     *              surName DirectoryString,
     *              givenName SEQUENCE OF DirectoryString
     *         },
     *            pseudonym DirectoryString
     *       }
     * </pre>
     * @param pseudonym pseudonym value to use.
     */
    public NameOrPseudonym(DirectoryString pseudonym)
    {
        this.pseudonym = pseudonym;
    }

    /**
     * Constructor from ASN1Sequence.
     * <p/>
     * The sequence is of type NameOrPseudonym:
     * <p/>
     * <pre>
     *       NameOrPseudonym ::= CHOICE {
     *            surAndGivenName SEQUENCE {
     *              surName DirectoryString,
     *              givenName SEQUENCE OF DirectoryString
     *         },
     *            pseudonym DirectoryString
     *       }
     * </pre>
     *
     * @param seq The ASN.1 sequence.
     */
    private NameOrPseudonym(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }

        if (!(seq.getObjectAt(0) instanceof DERString))
        {
            throw new IllegalArgumentException("Bad object encountered: "
                + seq.getObjectAt(0).getClass());
        }

        surname = DirectoryString.getInstance(seq.getObjectAt(0));

        givenName = new Vector();

        ASN1Sequence s = ASN1Sequence.getInstance(seq.getObjectAt(1));
        Enumeration e = s.getObjects();

        while (e.hasMoreElements())
        {
            Object o = e.nextElement();
            if (!(o instanceof DERString))
            {
                throw new IllegalArgumentException("Bad object encountered: " + o.getClass());
            }
            givenName.addElement(DirectoryString.getInstance(o));
        }
    }

    /**
     * Constructor from a given details.
     *
     * @param pseudonym The pseudonym.
     */
    public NameOrPseudonym(String pseudonym)
    {
        this.pseudonym = new DirectoryString(pseudonym);
    }

    /**
     * Constructor from a given details.
     *
     * @param surname   The surname.
     * @param givenName A vector of strings of the given name
     */
    public NameOrPseudonym(String surname, Vector givenName)
    {
        this.surname = new DirectoryString(surname);
        this.givenName = new Vector();
        for (Enumeration e = givenName.elements(); e.hasMoreElements();)
        {
            this.givenName.addElement(new DirectoryString((String)e.nextElement()));
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p/>
     * Returns:
     * <p/>
     * <pre>
     *       NameOrPseudonym ::= CHOICE {
     *            surAndGivenName SEQUENCE {
     *              surName DirectoryString,
     *              givenName SEQUENCE OF DirectoryString
     *         },
     *            pseudonym DirectoryString
     *       }
     * </pre>
     *
     * @return a DERObject
     */
    public DERObject toASN1Object()
    {
        if (pseudonym != null)
        {
            return pseudonym.toASN1Object();
        }
        else
        {
            ASN1EncodableVector vec1 = new ASN1EncodableVector();
            vec1.add(surname);
            ASN1EncodableVector vec2 = new ASN1EncodableVector();
            for (Enumeration e = givenName.elements(); e.hasMoreElements();)
            {
                vec2.add(new DERUTF8String(e.nextElement().toString()));
            }
            vec1.add(new DERSequence(vec2));
            return new DERSequence(vec1);
        }
    }
}
