package org.bouncycastle.cert.jcajce;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.x509.X509AttributeCertificate;

public class JcaAttrCertStore
    extends CollectionStore
{
    /**
     * Basic constructor.
     *
     * @param collection - initial contents for the store, this is copied.
     */
    public JcaAttrCertStore(Collection collection)
        throws IOException
    {
        super(convertCerts(collection));
    }

    private static Collection convertCerts(Collection collection)
        throws IOException
    {
        List list = new ArrayList(collection.size());

        for (Iterator it = collection.iterator(); it.hasNext();)
        {
            Object o = it.next();

            if (o instanceof X509AttributeCertificate)
            {
                X509AttributeCertificate cert = (X509AttributeCertificate)o;

                list.add(new JcaX509AttributeCertificateHolder(cert));
            }
            else
            {
                list.add((X509AttributeCertificateHolder)o);
            }
        }

        return list;
    }
}
