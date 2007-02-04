package org.bouncycastle.asn1.isismtt.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;

import java.util.Enumeration;
import java.util.Vector;

/**
 * Professions, specializations, disciplines, fields of activity, etc.
 * 
 * <pre>
 *               ProfessionInfo ::= SEQUENCE 
 *               {
 *                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
 *                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
 *                 professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
 *                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
 *                 addProfessionInfo OCTET STRING OPTIONAL 
 *               }
 * </pre>
 * 
 * @see org.bouncycastle.asn1.isismtt.x509.Admission
 */
public class ProfessionInfo extends ASN1Encodable
{

    /**
     * Rechtsanw�ltin
     */
    public static final DERObjectIdentifier Rechtsanwltin = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".1");

    /**
     * Rechtsanwalt
     */
    public static final DERObjectIdentifier Rechtsanwalt = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".2");

    /**
     * Rechtsbeistand
     */
    public static final DERObjectIdentifier Rechtsbeistand = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".3");

    /**
     * Steuerberaterin
     */
    public static final DERObjectIdentifier Steuerberaterin = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".4");

    /**
     * Steuerberater
     */
    public static final DERObjectIdentifier Steuerberater = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".5");

    /**
     * Steuerbevollm�chtigte
     */
    public static final DERObjectIdentifier Steuerbevollmchtigte = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".6");

    /**
     * Steuerbevollm�chtigter
     */
    public static final DERObjectIdentifier Steuerbevollmchtigter = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".7");

    /**
     * Notarin
     */
    public static final DERObjectIdentifier Notarin = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".8");

    /**
     * Notar
     */
    public static final DERObjectIdentifier Notar = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".9");

    /**
     * Notarvertreterin
     */
    public static final DERObjectIdentifier Notarvertreterin = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".10");

    /**
     * Notarvertreter
     */
    public static final DERObjectIdentifier Notarvertreter = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".11");

    /**
     * Notariatsverwalterin
     */
    public static final DERObjectIdentifier Notariatsverwalterin = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".12");

    /**
     * Notariatsverwalter
     */
    public static final DERObjectIdentifier Notariatsverwalter = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".13");

    /**
     * Wirtschaftspr�ferin
     */
    public static final DERObjectIdentifier Wirtschaftsprferin = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".14");

    /**
     * Wirtschaftspr�fer
     */
    public static final DERObjectIdentifier Wirtschaftsprfer = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".15");

    /**
     * Vereidigte Buchpr�ferin
     */
    public static final DERObjectIdentifier VereidigteBuchprferin = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".16");

    /**
     * Vereidigter Buchpr�fer
     */
    public static final DERObjectIdentifier VereidigterBuchprfer = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".17");

    /**
     * Patentanw�ltin
     */
    public static final DERObjectIdentifier Patentanwltin = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".18");

    /**
     * Patentanwalt
     */
    public static final DERObjectIdentifier Patentanwalt = new DERObjectIdentifier(
        NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".19");

    private NamingAuthority namingAuthority;

    private Vector professionItems;

    private Vector professionOIDs;

    private DERPrintableString registrationNumber;

    private DEROctetString addProfessionInfo;

    public static ProfessionInfo getInstance(Object obj)
    {
        if (obj == null || obj instanceof ProfessionInfo)
        {
            return (ProfessionInfo)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new ProfessionInfo((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
            + obj.getClass().getName());
    }

    /**
     * Constructor from ASN1Sequence.
     * <p/>
     * <p/>
     * <pre>
     *               ProfessionInfo ::= SEQUENCE
     *               {
     *                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
     *                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
     *                 professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
     *                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
     *                 addProfessionInfo OCTET STRING OPTIONAL
     *               }
     * </pre>
     *
     * @param seq The ASN.1 sequence.
     */
    private ProfessionInfo(ASN1Sequence seq)
    {
        if (seq.size() > 5)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }

        Enumeration e = seq.getObjects();

        DEREncodable o = (DEREncodable)e.nextElement();

        if (o instanceof ASN1TaggedObject)
        {
            if (((ASN1TaggedObject)o).getTagNo() != 0)
            {
                throw new IllegalArgumentException("Bad tag number: "
                    + ((ASN1TaggedObject)o).getTagNo());
            }
            namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject)o, true);
            o = (DEREncodable)e.nextElement();
        }
        Enumeration items = ((DERSequence)o).getObjects();
        professionItems = new Vector();
        while (items.hasMoreElements())
        {
            professionItems.addElement(DirectoryString.getInstance(items.nextElement()));
        }
        if (e.hasMoreElements())
        {
            o = (DEREncodable)e.nextElement();
            if (o instanceof DERSequence)
            {
                professionOIDs = new Vector();
                Enumeration oids = ((DERSequence)o).getObjects();
                while (oids.hasMoreElements())
                {
                    professionOIDs.addElement(oids.nextElement());
                }
            }
            else if (o instanceof DERPrintableString)
            {
                registrationNumber = DERPrintableString.getInstance(o);
            }
            else if (o instanceof DEROctetString)
            {
                addProfessionInfo = (DEROctetString)o;
            }
            else
            {
                throw new IllegalArgumentException("Bad object encountered: "
                    + o.getClass());
            }
        }
        if (e.hasMoreElements())
        {
            o = (DEREncodable)e.nextElement();
            if (o instanceof DERPrintableString)
            {
                registrationNumber = DERPrintableString.getInstance(o);
            }
            else if (o instanceof DEROctetString)
            {
                addProfessionInfo = (DEROctetString)o;
            }
            else
            {
                throw new IllegalArgumentException("Bad object encountered: "
                    + o.getClass());
            }
        }
        if (e.hasMoreElements())
        {
            o = (DEREncodable)e.nextElement();
            if (o instanceof DEROctetString)
            {
                addProfessionInfo = (DEROctetString)o;
            }
            else
            {
                throw new IllegalArgumentException("Bad object encountered: "
                    + o.getClass());
            }
        }

    }

    /**
     * Constructor from given details.
     * <p/>
     * <code>professionItems</code> is mandatory, all other parameters are
     * optional.
     *
     * @param namingAuthority    The naming authority.
     * @param professionItems    This vector contains text strings of the profession.
     * @param professionOIDs     The vector contains DERObjectIdentfier objects for the
     *                           profession.
     * @param registrationNumber Registration number.
     * @param addProfessionInfo  Additional infos in encoded form.
     */
    public ProfessionInfo(NamingAuthority namingAuthority,
                          Vector professionItems, Vector professionOIDs,
                          String registrationNumber, DEROctetString addProfessionInfo)
    {
        this.namingAuthority = namingAuthority;
        this.professionItems = new Vector(professionItems.size());

        for (Enumeration e = professionItems.elements(); e.hasMoreElements();)
        {
            this.professionItems.addElement(e.nextElement());
        }
        if (professionOIDs != null)
        {
            this.professionOIDs = new Vector(professionOIDs.size());
            for (Enumeration e = professionOIDs.elements(); e.hasMoreElements();)
            {
                this.professionOIDs.addElement(e.nextElement());
            }
        }
        this.registrationNumber = new DERPrintableString(registrationNumber, true);
        this.addProfessionInfo = addProfessionInfo;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p/>
     * Returns:
     * <p/>
     * <pre>
     *               ProfessionInfo ::= SEQUENCE
     *               {
     *                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
     *                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
     *                 professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
     *                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
     *                 addProfessionInfo OCTET STRING OPTIONAL
     *               }
     * </pre>
     *
     * @return a DERObject
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (namingAuthority != null)
        {
            vec.add(new DERTaggedObject(true, 0, namingAuthority));
        }
        ASN1EncodableVector items = new ASN1EncodableVector();
        for (Enumeration e = professionItems.elements(); e.hasMoreElements();)
        {
            items.add((DEREncodable)e.nextElement());
        }
        vec.add(new DERSequence(items));
        if (professionOIDs != null)
        {
            ASN1EncodableVector oids = new ASN1EncodableVector();
            for (Enumeration e = professionOIDs.elements(); e.hasMoreElements();)
            {
                oids.add((DERObjectIdentifier)e.nextElement());
            }
            vec.add(new DERSequence(oids));
        }
        if (registrationNumber != null)
        {
            vec.add(registrationNumber);
        }
        if (addProfessionInfo != null)
        {
            vec.add(addProfessionInfo);
        }
        return new DERSequence(vec);
    }

    /**
     * @return Returns the addProfessionInfo.
     */
    public DEROctetString getAddProfessionInfo()
    {
        return addProfessionInfo;
    }

    /**
     * @return Returns the namingAuthority.
     */
    public NamingAuthority getNamingAuthority()
    {
        return namingAuthority;
    }

    /**
     * @return Returns the professionItems.
     */
    public Vector getProfessionItems()
    {
        return professionItems;
    }

    /**
     * @return Returns the professionOIDs.
     */
    public Vector getProfessionOIDs()
    {
        return professionOIDs;
    }

    /**
     * @return Returns the registrationNumber.
     */
    public String getRegistrationNumber()
    {
        return registrationNumber.getString();
    }

}
