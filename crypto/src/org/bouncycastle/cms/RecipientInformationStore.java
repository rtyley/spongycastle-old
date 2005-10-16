package org.bouncycastle.cms;

import java.util.Collection;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

public class RecipientInformationStore
{
    private Map table = new HashMap();

    public RecipientInformationStore(
        Collection  recipientInfos)
    {
        Iterator    it = recipientInfos.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            table.put(recipient.getRID(), recipient);
        }
    }

    public RecipientInformation get(
        RecipientId        selector)
    {
        return (RecipientInformation)table.get(selector);
    }

    public int size()
    {
        return table.size();
    }

    public Collection getRecipients()
    {
        return table.values();
    }
}
