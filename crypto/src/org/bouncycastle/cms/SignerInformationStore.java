package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.List;

public class SignerInformationStore
{
    private Map table = new HashMap();

    public SignerInformationStore(
        Collection  signerInfos)
    {
        Iterator    it = signerInfos.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            SignerId            sid = signer.getSID();

            if (table.get(sid) == null)
            {
                table.put(sid, signer);
            }
            else
            {
                Object o = table.get(sid);
                
                if (o instanceof List)
                {
                    ((List)o).add(signer);
                }
                else
                {
                    List l = new ArrayList();
                    
                    l.add(o);
                    l.add(signer);
                    
                    table.put(sid, l);
                }
            }
        }
    }

    /**
     * Return the first SignerInformation object that matches the
     * passed in selector. Null if there are no matches.
     * 
     * @param selector to identify a signer
     * @return a single SignerInformation object. Null if none matches.
     */
    public SignerInformation get(
        SignerId        selector)
    {
        Object o = table.get(selector);
        
        if (o instanceof List)
        {
            return (SignerInformation)((List)o).get(0);
        }
        else
        {
            return (SignerInformation)o;
        }
    }

    /**
     * Return the number of signers in the collection.
     * 
     * @return number of signers identified.
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
     * Return all signers in the collection
     * 
     * @return a collection of signers.
     */
    public Collection getSigners()
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
     * Return possible empty collection with signers matching the passed in SignerId
     * 
     * @param selector a signer id to select against.
     * @return a collection of SignerInformation objects.
     */
    public Collection getSigners(
        SignerId selector)
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
