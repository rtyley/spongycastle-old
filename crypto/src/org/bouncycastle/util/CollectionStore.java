package org.bouncycastle.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class CollectionStore
    implements Store
{
    private List _local = new ArrayList();

    public CollectionStore(
        Collection collection)
    {
        _local.addAll(collection);
    }

    public Collection getMatches(Selector selector)
    {
        if (selector == null)
        {
            return new ArrayList(_local);
        }
        else
        {
            List col = new ArrayList();
            Iterator iter = _local.iterator();

            while (iter.hasNext())
            {
                Object obj = iter.next();

                if (selector.match(obj))
                {
                    col.add(obj);
                }
            }

            return col;
        }
    }
}
