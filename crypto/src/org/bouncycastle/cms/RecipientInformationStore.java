package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class RecipientInformationStore
{
    private Map table = new HashMap();

    public RecipientInformationStore(
        Collection  recipientInfos)
    {
        Iterator    it = recipientInfos.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipientInformation = (RecipientInformation)it.next();
            RecipientId            rid = recipientInformation.getRID();

            if (table.get(rid) == null)
            {
                table.put(rid, recipientInformation);
            }
            else
            {
                Object o = table.get(rid);

                if (o instanceof List)
                {
                    ((List)o).add(recipientInformation);
                }
                else
                {
                    List l = new ArrayList();

                    l.add(o);
                    l.add(recipientInformation);

                    table.put(rid, l);
                }
            }
        }
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
        Object o = table.get(selector);

        if (o instanceof List)
        {
            return (RecipientInformation)((List)o).get(0);
        }
        else
        {
            return (RecipientInformation)o;
        }
    }

    /**
     * Return the number of recipients in the collection.
     *
     * @return number of recipients identified.
     */
    public int size()
    {
        Iterator    it = table.values().iterator();
        int         count = 0;

        while (it.hasNext())
        {
            Object o = it.next();

            if (o instanceof List)
            {
                count += ((List)o).size();
            }
            else
            {
                count++;
            }
        }

        return count;
    }

    /**
     * Return all recipients in the collection
     *
     * @return a collection of recipients.
     */
    public Collection getRecipients()
    {
        List        list = new ArrayList(table.size());
        Iterator    it = table.values().iterator();

        while (it.hasNext())
        {
            Object o = it.next();

            if (o instanceof List)
            {
                list.addAll((List)o);
            }
            else
            {
                list.add(o);
            }
        }

        return list;
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
        Object o = table.get(selector);

        if (o instanceof List)
        {
            return new ArrayList((List)o);
        }
        else if (o != null)
        {
            return Collections.singletonList(o);
        }

        return new ArrayList();
    }
}
