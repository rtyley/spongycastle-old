package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.attr.ImageAttribute;

import java.util.ArrayList;
import java.util.List;

public class PGPUserAttributeSubpacketVectorGenerator
{
    private List list = new ArrayList();

    public void setImageAttribute(ImageAttribute attribute)
    {
        if (attribute == null)
        {
            throw new IllegalArgumentException("attempt to set null ImageAttribute");
        }

        list.add(attribute);
    }

    public PGPUserAttributeSubpacketVector generate()
    {
        return new PGPUserAttributeSubpacketVector((UserAttributeSubpacket[])list.toArray(new UserAttributeSubpacket[list.size()]));
    }
}
