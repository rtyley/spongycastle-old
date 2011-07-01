package org.bouncycastle.cms;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;

public class RecipientInformationStore
{
    private final List      all; //ArrayList[RecipientInformation]
    private final Map       table = new HashMap(); // HashMap[RecipientID, ArrayList[RecipientInformation]]

    public RecipientInformationStore(
        Collection  recipientInfos)
    {
        Iterator it = recipientInfos.iterator();

        while (it.hasNext())
        {
            RecipientInformation recipientInformation = (RecipientInformation)it.next();
            RecipientId rid = recipientInformation.getRID();

            List list = (ArrayList)table.get(rid);
            if (list == null)
            {
                list = new ArrayList(1);
                table.put(rid, list);
            }

            list.add(recipientInformation);
        }

        this.all = new ArrayList(recipientInfos);
    }

    /**
     * Return the first RecipientInformation object that matches the
     * passed in selector. Null if there are no matches.
     *
     * @param selector to identify a recipient
     * @return a single RecipientInformation object. Null if none matches.
     */
    public RecipientInformation get(
        RecipientId selector)
    {
        Collection list = getRecipients(selector);

        return list.size() == 0 ? null : (RecipientInformation) list.iterator().next();
    }

    /**
     * Return the number of recipients in the collection.
     *
     * @return number of recipients identified.
     */
    public int size()
    {
        return all.size();
    }

    /**
     * Return all recipients in the collection
     *
     * @return a collection of recipients.
     */
    public Collection getRecipients()
    {
        return new ArrayList(all);
    }

    /**
     * Return possible empty collection with recipients matching the passed in RecipientId
     *
     * @param selector a recipient id to select against.
     * @return a collection of RecipientInformation objects.
     */
    public Collection getRecipients(
        RecipientId selector)
    {
        if (selector.getIssuer() != null && selector.getSubjectKeyIdentifier() != null)
        {
            List results = new ArrayList();
            try
            {
                Collection match1 = getRecipients(new KeyTransRecipientId(X500Name.getInstance(selector.getIssuerAsBytes()), selector.getSerialNumber()));

                if (match1 != null)
                {
                    results.addAll(match1);
                }
            }
            catch (IOException e)
            {
                // ignore...
            }

            Collection match2 = getRecipients(new KeyTransRecipientId(ASN1OctetString.getInstance(selector.getSubjectKeyIdentifier()).getOctets()));

            if (match2 != null)
            {
                results.addAll(match2);
            }

            return results;
        }
        else
        {
            List list = (ArrayList)table.get(selector);

            return list == null ? new ArrayList() : new ArrayList(list);
        }
    }
}
